import os

import saml2
import saml2.saml

# configurações de ambiente
DOMAIN = "dev.gidlab.rnp.br"
PORT = "8080"
FQDN = "http://"+DOMAIN+":"+PORT
CERT_DIR = "certificates"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SECRET_KEY = 'mzqqgr@mrk@4$)#4g(v*fdksrubct31xf*u)xwo=5v1zze+hd+'

DEBUG = True

ALLOWED_HOSTS = [
    '*'
]

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'base',
    'djangosaml2', #incluindo nova app djangosaml2 
]

# Incluindo o backend de autenticação Saml2Backend
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend', 
    'djangosaml2.backends.Saml2Backend',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Inclui o middleware saml2
MIDDLEWARE.append('djangosaml2.middleware.SamlSessionMiddleware')

ROOT_URLCONF = 'sp_django.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'sp_django.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'America/Sao_Paulo'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.0/howto/static-files/
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')

#---------- CONFIGURACOES SAML -----------
SAML_SESSION_COOKIE_NAME = 'saml_session'
SESSION_COOKIE_SAMESITE = None

# Qualquer view que requer um usuário autenticado deve redirecionar o navegador esta url 
LOGIN_URL = '/saml2/login/' 

# Encerra a sessão quando o usuário fecha o navegador
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Tipo de binding utilizado
SAML_DEFAULT_BINDING = saml2.BINDING_HTTP_POST  
SAML_IGNORE_LOGOUT_ERRORS = True

# Serviço de descoberta da cafeexpresso
SAML2_DISCO_URL = 'https://ds.cafeexpresso.rnp.br/WAYF.php'

# Cria usuário Django a partir da asserção SAML caso o mesmo não exista
SAML_CREATE_UNKNOWN_USER = True 

# URL para redirecionamento após a autenticação
LOGIN_REDIRECT_URL = '/users'

# Mapeamento de atributos de usuário SAML2 para atributos de usuário Django 
SAML_ATTRIBUTE_MAPPING = {
    'eduPersonPrincipalName': ('username', ),
    'mail': ('email', ),
    'givenName': ('first_name', ),
    'sn': ('last_name', ),
}

SAML_CONFIG = {

  # Biblioteca usada para assinatura e criptografia
  'xmlsec_binary': '/usr/bin/xmlsec1',

  'entityid': FQDN + '/saml2/metadata/',

  # Diretório contendo os esquemas de mapeamento de atributo
  'attribute_map_dir': os.path.join(BASE_DIR, 'attribute-maps'), 
  
  'description': 'SP Implicit',
  
  # Serviços a qual o servidor irá fornecer
  'service': {
      'sp' : {
          'name': 'SP Django Implicit',
          'ui_info': {
                'display_name': {'text':'SP Django Implicit',
                                 'lang':'en'},
                'description': {'text':'Provedor de serviços Django Implicit',
                                'lang':'en'},
                'information_url': {'text':'http://sp.information.url/',
                                    'lang':'en'},
                'privacy_statement_url': {'text':'http://sp.privacy.url/',
                                          'lang':'en'}
                },
  
          'name_id_format': [
                "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", 
                "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
          ],

          # Indica os endpoints dos serviços fornecidos
          'endpoints': {
              'assertion_consumer_service': [
                  (FQDN +'/saml2/acs/',
                   saml2.BINDING_HTTP_POST),
                  ],
              'single_logout_service': [
                  (FQDN + '/saml2/ls/',
                   saml2.BINDING_HTTP_REDIRECT),
                  (FQDN + '/saml2/ls/post',
                   saml2.BINDING_HTTP_POST),
                  ],
          },

          # Algoritmos utilizados
          'signing_algorithm':  saml2.xmldsig.SIG_RSA_SHA256,
          'digest_algorithm':  saml2.xmldsig.DIGEST_SHA256,

          'force_authn': False,

          'name_id_format_allow_create': False,

          # Indica que as respostas de autenticação para este SP devem ser assinadas
          'want_response_signed': True,
          
          # Indica se as solicitações de autenticação enviadas por este SP devem ser assinadas
          'authn_requests_signed': True,

          # Indica se este SP deseja que o IdP envie as asserções assinadas
          'want_assertions_signed': True,

          'only_use_keys_in_metadata': True,

          'allow_unsolicited': False,
          },
      },
  # Indica onde os metadados podem ser encontrados
  'metadata': {
      'remote': [{"url": "https://ds.cafeexpresso.rnp.br/metadata/ds-metadata.xml","cert": "null"},]
      },

  # Configurado como 1 para fornecer informações de debug 
  'debug': 1,

  # Assinatura
  'key_file': os.path.join(BASE_DIR, CERT_DIR, 'mykey.pem'),  # private part
  'cert_file': os.path.join(BASE_DIR, CERT_DIR, 'mycert.pem'),  # public part

  # Encriptação
  'encryption_keypairs': [{
      'key_file': os.path.join(BASE_DIR, CERT_DIR, 'mykey.pem'),  # private part
      'cert_file': os.path.join(BASE_DIR, CERT_DIR, 'mycert.pem'),  # public part
  }],

  # Descreve a pessoa responsável pelo serviço
  'contact_person': [
      {'given_name': 'GIdLab',
       'sur_name': 'Equipe',
       'company': 'RNP',
       'email_address': 'gidlab@rnp.br',
       'contact_type': 'technical'},
      ],

  # Descreve a organização responsável pelo serviço    
  'organization': {
      'name': [('GIdLab', 'pt-br')],
      'display_name': [('GIdLab', 'pt-br')],
      'url': [('http://gidlab.rnp.br', 'pt-br')],
    },
  }
