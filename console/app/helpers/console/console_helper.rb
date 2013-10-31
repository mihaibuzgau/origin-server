module Console::ConsoleHelper

  #FIXME: Replace with real isolation of login state
  def logout_path
    nil
  end

  def outage_notification
  end

  def product_branding
    [
      image_tag('/assets/logo-enterprise-horizontal.svg', :alt => 'OpenShift Enterprise')
    ].join.html_safe
  end

  def product_title
    'OpenShift Enterprise'
  end
end
