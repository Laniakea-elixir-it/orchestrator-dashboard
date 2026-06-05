
#### LOOK AND FEEL SETTINGS
WELCOME_MESSAGE = "Welcome to Laniakea"
NAVBAR_BRAND_TEXT = "Laniakea Dashboard"
NAVBAR_BRAND_ICON = "https://raw.githubusercontent.com/Laniakea-elixir-it/resources/master/logos/ELIXIR_ITALY_orange.png"
### SSH access
FEATURE_REQUIRE_USER_SSH_PUBKEY = "yes"
### Template Paths
HOME_TEMPLATE = 'laniakea/home.html'
PORTFOLIO_TEMPLATE = 'laniakea/portfolio.html'
MAIL_TEMPLATE = 'laniakea/email.html'
FOOTER_TEMPLATE = 'laniakea/footer.html'
### Extras
# LUKS api
EXTRA_FEATURE_LUKS_API_INTEGRATION = "yes"
EXTRA_FEATURE_LUKS_API_PORT = "5000"
EXTRA_FEATURE_LUKS_API_HTTPS = "yes"
EXTRA_FEATURE_LUKS_API_STATUS = "/luksctl_api/v1.0/status"
EXTRA_FEATURE_LUKS_API_OPEN = "/luksctl_api/v1.0/open"
# Laniakea-utils api
EXTRA_FEATURE_LANIAKEA_UTILS_INTEGRATION = "yes"
EXTRA_FEATURE_LANIAKEA_UTILS_PORT = "5001"
EXTRA_FEATURE_LANIAKEA_UTILS_HTTPS = "no" #TODO
EXTRA_FEATURE_LANIAKEA_UTILS_GALAXY_STARTUP = "/galaxyctl_api/v1.0/galaxy-startup"
# Laniakea-nebula
EXTRA_FEATURE_LANIAKEA_NEBULA_INTEGRATION = "yes"
