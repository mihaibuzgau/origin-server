require "openshift-origin-common/utils/path_utils"
require "openshift-origin-common/config"
require "openshift-origin-node/utils/environ"
require "fileutils"

module OpenShift
  class GearUpgradeExtension

    # When renaming cartridge's versions...
    #
    # Hash key(String) => value(String)
    # cartridge name + '-' + old version => new version
    VERSION_MAP = {
      'phpmyadmin-3'        => '4',
      'phpmyadmin-3.4'      => '4',
      'jbosseap-6.0'        => '6',
      'jenkins-1.4'         => '1',
      'jenkins-client-1.4'  => '1',
      'switchyard-0.6'      => '0',
    }

    DEPENDENCIES_MAP = {
      'php' => {
        normal: [{'php/phplib' => nil}],
        build: []
      },
      'jbossas' => {
        normal: [{'jbossas/standalone/deployments' => 'jbossas/deployments'}],
        build: [{'.m2' => nil}]
      },
      'jbosseap' => {
        normal: [{'jbosseap/standalone/deployments' => 'jbosseap/deployments'}],
        build: [{'.m2' => nil}]
      },
      'jbossews' => {
        normal: [{'jbossews/webapps' => nil}],
        build: [{'.m2' => nil}]
      },
      'nodejs' => {
        normal: [{'.npm' => nil}, {'nodejs/node_modules' => nil}, {'.node_modules' => 'nodejs/node_modules'}],
        build: []
      },
      'perl' => {
        normal: [{'.cpanm' => nil}],
        build: []
      },
      'python' => {
        normal: [{'python/virtenv' => nil}],
        build: []
      },
      'zend' => {
        normal: [{'zend/phplib' => nil}],
        build: []
      }
    }

    def self.version
      '2'
    end

    def initialize(upgrader)
      @upgrader  = upgrader
      @uuid      = upgrader.uuid
      @gear_home = upgrader.gear_home
      @container = upgrader.container
    end

    def pre_upgrade(progress)
      path = File.join(@gear_home, '.env', 'user_vars')
      progress.log "Creating #{path}"
      FileUtils.mkpath(path)
      FileUtils.chmod(0770, path)
      @container.set_ro_permission(path)

      progress.log 'Setting gear broker auth'
      if @upgrader.gear_env['OPENSHIFT_APP_DNS'] && (@upgrader.gear_env['OPENSHIFT_APP_DNS'] == @upgrader.gear_env['OPENSHIFT_GEAR_DNS']) && @upgrader.auth_iv && @upgrader.auth_token
        @upgrader.container.add_broker_auth(@upgrader.auth_iv, @upgrader.auth_token) unless File.exist? File.join(@gear_home, '.auth', 'token')
      end

      progress.log "Setting gear HOME to #{@gear_home}"
      @upgrader.container.add_env_var('HOME', @gear_home, false)

      progress.log "Setting gear OPENSHIFT_APP_UUID to #{@upgrader.application_uuid}"
      @upgrader.container.add_env_var("APP_UUID", @upgrader.application_uuid, true)

      progress.log 'Setting gear memory'
      @container.add_env_var('GEAR_MEMORY_MB', (@container.memory_in_bytes() / 1024**2).to_s, true)

      progress.log 'Setting gear OPENSHIFT_SECRET_TOKEN'
      @upgrader.container.add_env_var('SECRET_TOKEN', @upgrader.secret_token, true)

      # Add GEM_DIR to gear env variables, prior to 2.0.30 this variable was not present
      progress.log 'Setting gear GEM_DIR'
      @container.add_env_var("GEM_DIR", File.join(@gear_home, '.gem'), false)
    end

    unless VERSION_MAP.empty?
      def map_ident(progress, ident)
        vendor, name, version, cartridge_version = OpenShift::Runtime::Manifest.parse_ident(ident)
        name_version                             = "#{name}-#{version}"

        if VERSION_MAP[name_version]
          progress.log "Mapping version #{version} to #{VERSION_MAP[name_version]} for cartridge #{name}"
          version = VERSION_MAP[name_version] || version
        end

        return vendor, name, version, cartridge_version
      end
    end

    def pre_cartridge_upgrade(progress, itinerary)
      # Create OPENSHIFT_RUBY_PATH_ELEMENT if it doesn't exist, as of 2.0.30 both ruby-1.8 
      # and ruby-1.9 carts use this variable, previously it was only ruby-1.9.  Without setting
      # this variable upgraded ruby-1.8 carts will fail on git push.
      path = File.join(@gear_home, 'ruby')
      if File.directory? path
        rpe = File.join(path, 'env', 'OPENSHIFT_RUBY_PATH_ELEMENT')
        if (! File.file? rpe) and (@upgrader.gear_env['OPENSHIFT_RUBY_VERSION'] == "1.8")
          IO.write(rpe, File.join(@gear_home, '.gem', '/bin'))
        end
      end

      # Replace any jbossews symlinked webapps directories with a physical directory
      # Was performed in 2.0.29 using cartridge setup script
      path = File.join(@gear_home, 'jbossews')
      webappsdir = File.join(path, 'webapps')
      if File.directory? path and File.symlink? webappsdir
        FileUtils.rm_f webappsdir
        FileUtils.mkdir_p webappsdir
        webappssrc = File.join(@gear_home, 'app-root/runtime/repo/webapps/*')
        FileUtils.mv(Dir.glob(webappssrc), webappsdir)
      end

      # Repair @gear_home/jbosseap/ symlinks to /etc/alternatives/ links.
      jboss_version = '6'
      jboss_home = "/etc/alternatives/jbosseap-#{jboss_version}"
      path = File.join(@gear_home, 'jbosseap')
      if File.directory? path
        progress.log "Fixing jbosseap/jboss-modules.jar symlink for #{@uuid}"
        FileUtils.ln_sf(File.join(jboss_home, 'jboss-modules.jar'), File.join(path, 'jboss-modules.jar'))
        progress.log "Fixing jbosseap/modules symlink for #{@uuid}"
        FileUtils.ln_sf(File.join(jboss_home, 'modules'), File.join(path, 'modules'))
      end

      # Repair OPENSHIFT_JBOSSEAP_VERSION env. var.
      path = File.join(@gear_home, 'jbosseap', 'env', 'OPENSHIFT_JBOSSEAP_VERSION')
      if File.file? path
        progress.log "Fixing OPENSHIFT_JBOSSEAP_VERSION environment variable for #{@uuid}"
        FileUtils.rm path
        IO.write(path, jboss_version)
      end

      # Patch Jenkins jobs' config.xml for the renaming of jbosseap-6.0 to jbosseap-6.
      path = File.join(@gear_home, 'jenkins')
      if File.directory? path
        progress.log "Patching jenkins builderType for #{@uuid}"
        file = "#{@gear_home}/app-root/data/jobs/*/config.xml"
        sep = ','
        old_value = 'jbosseap-6\.0'
        new_value = 'jbosseap-6'
        output = `sed -i "s#{sep}#{old_value}#{sep}#{new_value}#{sep}g" #{file} 2>&1`
        exitcode = $?.exitstatus
        progress.log "Updated '#{file}' changed '#{old_value}' to '#{new_value}'.  output: #{output}  exitcode: #{exitcode}"
      end

      # XXX jbossas/jbosseap fix from agolste

      if itinerary.has_entry_for?('haproxy-1.4')
        migrate_gear_registry(progress)
      end

      @container.cartridge_model.each_cartridge do |cartridge|
        next if not ['jbossas','jbosseap'].include? cartridge.name
        proxy_port_name = "OPENSHIFT_#{cartridge.name.upcase}_MESSAGING_THROUGHPUT_PROXY_PORT"
        gear_env = ::OpenShift::Runtime::Utils::Environ.for_gear(@container.container_dir)
        if gear_env.has_key?(proxy_port_name)
          proxy = ::OpenShift::Runtime::FrontendProxyServer.new
          proxy.system_proxy_delete(gear_env[proxy_port_name])
          @container.remove_env_var(proxy_port_name)
        end
      end

      migrate_deployment_system_pre(progress)
    end

    def post_cartridge_upgrade(progress, itinerary)
      migrate_deployment_system_post(progress)
    end

    def migrate_deployment_system_pre(progress)
      progress.step 'migrate_deployment_system' do
        progress.step 'add_deployments_dir' do
          deployments_dir = PathUtils.join(@gear_home, "app-deployments") + "/"

          unless Dir.exists?(deployments_dir)
            @container.add_env_var("DEPLOYMENTS_DIR", deployments_dir, true) {|v|
              FileUtils.mkdir_p("#{v}/by-id", :verbose => true)
              @container.set_rw_permission_R(deployments_dir)
            }

            progress.log "Created deployments directory"
          end
        end

        progress.step 'create_dep_symlinks' do
          @container.add_env_var("DEPENDENCIES_DIR", PathUtils.join(@gear_home, "app-root", "runtime", "dependencies") + "/", true) do |d|
            FileUtils.mkdir_p(d, verbose: true)
            progress.log "Created dir #{d}"

            @container.set_rw_permission_R(d)
          end

          @container.add_env_var("BUILD_DEPENDENCIES_DIR", PathUtils.join(@gear_home, "app-root", "runtime", "build-dependencies") + "/", true) do |d|
            FileUtils.mkdir_p(d, verbose: true)
            progress.log "Created dir #{d}"

            @container.set_rw_permission_R(d)
          end

          FileUtils.ln_sf("#{@gear_home}/app-root/runtime/dependencies", "#{@gear_home}/app-root/dependencies", verbose: true)
          FileUtils.ln_sf("#{@gear_home}/app-root/runtime/build-dependencies", "#{@gear_home}/app-root/build-dependencies", verbose: true)
          PathUtils.oo_lchown(@container.uid, @container.gid, "#{@gear_home}/app-root/dependencies", "#{@gear_home}/app-root/build-dependencies")

          progress.log "Created dependency directories, links, and env vars"
        end

        progress.step 'restore_repo' do
          deployments = @container.all_deployments

          progress.step 'create_initial_deployment_dir' do
            if deployments.length == 0
              @container.create_deployment_dir

              progress.log "Created initial deployment directory"

              deployments = @container.all_deployments
              deployment_datetime = File.basename(deployments[0])

              deployment_id = @container.calculate_deployment_id(deployment_datetime)
              @container.link_deployment_id(deployment_datetime, deployment_id)
              deployment_metadata = @container.deployment_metadata_for(deployment_datetime)
              deployment_metadata.id = deployment_id
              deployment_metadata.record_activation
              deployment_metadata.save
              @container.update_current_deployment_datetime_symlink(deployment_datetime)

              progress.log "Updated links and recorded activation for deployment #{deployment_datetime}"
            end
          end

          unless deployments.length == 1
            errors << "Expected just 1 deployment to exist during upgrade, but found #{deployments.length}; cannot proceed"
            return
          end
        end

        progress.step 'move_cart_dependencies' do
          @container.cartridge_model.each_cartridge do |cartridge|
            next unless DEPENDENCIES_MAP.has_key?(cartridge.name)

            (DEPENDENCIES_MAP[cartridge.name][:build] + DEPENDENCIES_MAP[cartridge.name][:normal]).each do |entry|
              dep_dir = entry.keys[0]
              dep_path = PathUtils.join(@container.container_dir, dep_dir)
              if dep_dir == "nodejs/node_modules"
                FileUtils.rm_f(dep_path)
                next
              end
              next if File.symlink?(dep_path)
              backup_path = "#{dep_path}.backup"
              unless Dir.exists?(backup_path)
                FileUtils.mv(dep_path, backup_path)
                progress.log "Backed up cartridge #{cartridge.name} dependency #{dep_dir}"
              end
            end

            create_dependency_directories(cartridge)
            progress.log "Created cartridge dependency dirs for #{cartridge.name}"

            (DEPENDENCIES_MAP[cartridge.name][:build] + DEPENDENCIES_MAP[cartridge.name][:normal]).each do |entry|
              dep_dir = entry.keys[0]
              dep_path = PathUtils.join(@container.container_dir, dep_dir)
              next if dep_dir == "nodejs/node_modules"
              backup_path = "#{dep_path}.backup"
              if Dir.exists?(backup_path)
                raise "Expected dependency dir symlink to exist at #{dep_path}" unless File.symlink?(dep_path)
                progress.log("Restoring dep backup from #{backup_path} based on dep_dir #{dep_dir} and dep_path #{dep_path}")
                if `ls -1 #{backup_path} | wc -l`.to_i > 0
                  out = `shopt -s dotglob; mv #{PathUtils.join(backup_path, "*")} #{dep_path} 2>&1`
                  raise "Couldn't move dep contents from #{backup_path} to #{dep_path}: #{out}" unless $? == 0
                end
                FileUtils.rm_rf(backup_path)
                progress.log "Restored cartridge #{cartridge.name} dependencies to #{dep_path}"
              end
            end
          end
        end
      end
    end

    def migrate_deployment_system_post(progress)
      progress.step 'populate_deployment_dir' do |context, errors|
        progress.log @container.check_deployments_integrity
        deployment_datetime = @container.current_deployment_datetime

        if deployment_datetime.nil?
          errors << "Cannot continue migrating gear registry; no deployment datetime"
          return
        end

        @container.sync_runtime_repo_dir_to_deployment(deployment_datetime)
        @container.sync_runtime_dependencies_dir_to_deployment(deployment_datetime)
        @container.sync_runtime_build_dependencies_dir_to_deployment(deployment_datetime)
      end
    end

    def migrate_gear_registry(progress)
      progress.step "upgrade_gear_registry" do |context,errors|
        haproxy_cfg = File.join(@gear_home, %w(haproxy conf haproxy.cfg))
        legacy_gear_registry = File.join(@gear_home, %w(haproxy conf gear-registry.db))
        platform_registry_file = PathUtils.join(@container.container_dir, 'gear-registry', 'gear-registry.json')

        if !File.exists?(legacy_gear_registry)
          if !File.exists?(platform_registry_file)
            errors << "Gear has neither a legacy nor a platform gear registry file"
          end

          return # either way, we're done
        end

        progress.log "Migrating haproxy gear registry"

        legacy_content = IO.read(legacy_gear_registry)

        platform_registry = ::OpenShift::Runtime::GearRegistry.new(@container)
        env = ::OpenShift::Runtime::Utils::Environ.for_gear(@gear_home)

        namespace = env['OPENSHIFT_NAMESPACE']

        legacy_content.each_line do |line|
          options = {}
          parts = line.split(';')

          dns = parts[1]
          options[:dns] = dns
          options[:uuid] = dns.split('-')[0]
          options[:namespace] = namespace

          uuid_and_namespace = "#{options[:uuid]}-#{namespace}"

          cfg_entry, _, rc = ::OpenShift::Runtime::Utils.oo_spawn("grep #{uuid_and_namespace} #{haproxy_cfg}")

          if rc == 0
            proxy_host_and_port = cfg_entry.split(' ')[2]
            options[:proxy_hostname] = proxy_host_and_port.split(':')[0]
            options[:proxy_port] = proxy_host_and_port.split(':')[1]
            options[:type] = 'web'

            platform_registry.add(options)
          else
            progress.log "Unable to locate #{uuid_and_namespace} in #{haproxy_cfg}, skipping."
          end
        end

        progress.log "Added entries from existing haproxy gear registry"

        config = ::OpenShift::Config.new

        options = {}
        options[:dns] = env['OPENSHIFT_GEAR_DNS']
        options[:uuid] = @container.uuid
        options[:namespace] = namespace

        proxy_port_name = @container.cartridge_model.primary_cartridge.public_endpoints.first.public_port_name
        options[:proxy_port] = env[proxy_port_name]
        options[:proxy_hostname] = config.get('PUBLIC_HOSTNAME')
        options[:type] = 'web'

        platform_registry.add(options)

        options[:type] = 'proxy'
        options[:proxy_port] = 0

        platform_registry.add(options)
        platform_registry.save

        FileUtils.rm_f(legacy_gear_registry)

        progress.log "Added entries for proxy gear"
      end
    end

    # Copied here from the cartridge model because we don't have any way to inspect the resolved
    # managed_files from the "next" version of the cartridge
    def create_dependency_directories(cartridge)
      %w(build-dependencies dependencies).each do |dependencies_dir_name|
        if dependencies_dir_name == 'build-dependencies'
          dirs = DEPENDENCIES_MAP[cartridge.name][:build]
        else
          dirs = DEPENDENCIES_MAP[cartridge.name][:normal]
        end

        dirs.each do |entry|
          if entry.values[0].nil?
            # e.g. phplib
            link = target = entry.keys[0]
          else
            # e.g. jbossas/standalone/deployments
            link = entry.keys[0]

            # e.g. jbossas/deployments
            target = entry.values[0]
          end

          # create the target dir inside the runtime dir
          dependencies_dir = PathUtils.join(@container.container_dir, 'app-root', 'runtime', dependencies_dir_name)

          FileUtils.mkdir_p(PathUtils.join(dependencies_dir, target))

          full_link = PathUtils.join(@container.container_dir, link)

          # if the link is something like foo/bar/baz or jbossas/standalone/deployments,
          # need to mkdir -p everything up to the link (foo/bar or jbossas/standalone)
          #
          # also need to chown -R the first directory in the path that is new, e.g.
          # if jbossas exists but standalone is new, chown -R standalone
          if link.count('/') > 0
            parts = link.split('/')

            # start the path at the home dir
            path = @container.container_dir

            parts.each do |part|
              # check each segment of the link
              path = PathUtils.join(path, part)

              # if the path exists, skip to the next one
              next if File.exist?(path)

              # if the path doesn't exist, exit the loop
              #
              # path is now either the first dir in the link's path that doesn't exist
              # or it's the link itself
              break
            end

            # now that we've figured out the portion of the link path that doesn't exist
            # go ahead and create all the parent dirs for the link
            FileUtils.mkdir_p(PathUtils.join(@container.container_dir, parts[0..-2]))

            # if the path != the full link, we need to change ownership for the new
            # dir and below
            if path != full_link
              PathUtils.oo_chown_R(@container.uid, @container.gid, path)
            end
          end

          full_target = PathUtils.join(@container.container_dir, 'app-root', 'runtime', dependencies_dir_name, target)

          # the link only needs to be created when the cartridge is installed,
          # which means it's running via mcollective as root
          #
          # once the link exists, it should never need to change and does not
          # need to be recreated during a clean build
          if !File.exist?(full_link)
            FileUtils.ln_s(full_target, full_link)

            # make sure the symlink is owned by the gear user
            PathUtils.oo_lchown(@container.uid, @container.gid, full_link)
          end

          # in case anything was created below the dependencies dir, correct its ownership
          PathUtils.oo_chown_R(@container.uid, @container.gid, dependencies_dir)
        end
      end
    end
  end
end
