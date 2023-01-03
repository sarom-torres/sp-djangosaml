# Aplicação exemplo usando Djangosaml2

## Preparando ambiente de instalação

Instale as bibliotecas mínimas necessárias para o funcionamento do djangosaml2.
```console
$ sudo apt install python3-pip xmlsec python3-dev libssl-dev libsasl2-dev
```
Instale, crie e ative o ambiente virtual.
```console
$ pip3 install virtualenv
$ mkdir [nome-diretorio] && cd [nome-diretorio] 
$ virtualenv env
$ source env/bin/activate
```
Instale o djangosaml2
```console
$ pip install djangosaml2
```

## Configurações do projeto

O projeto possui a seguinte estrutura geral:
```
sp-django-python
├── attribute-maps
│   ├── basic.py
│   └── saml_uri.py
├── base
│   └── views.py
├── certificates
│   ├── mycert.pem
│   └── mykey.pem
├── manage.py
├── requirements.txt
└── sp_django
    ├── settings.py
    └── urls.py
```
Em que:
- `sp-django-python`: diretório principal do projeto.
- `attribute-maps`: diretório para os arquivos contendo os mapeamento de atributos.
- `base`: diretório da aplicação base.
- `certificates`: diretório contendo os certificados.
- `sp_django`: diretório contendo as configurações do projeto.

Crie o diretório `certificates` com o seguinte comando:
```console
$ mkdir certificates 
```
Inclua no diretório seus certificados para assinatura e encriptação das asserções SAML. Caso não possua certificados válidos gere um certificado autoassinado através do comando abaixo:
```console
# criando chave
$ openssl genrsa -out mykey.key 2048

# mudando permissões de leitura e escrita da chave
$ chmod 600 mykey.key

# criando certificado a partir da chave
$ openssl req -new -key mykey.key -out mycert.csr
$ openssl x509 -req -days 365 -in mycert.csr -signkey mykey.key -out mycert.crt

$  cp server.key mykey.pem
$  cp server.crt mycert.pem
```

> É possível utilizar o mesmo certificado tanto para assinatura como para encriptação.


## Editando o arquivo definições da aplicação

> As edições a seguir devem ser feitas no arquivo `settings.py` do projeto.

### Configurações gerais SAML 
Importe a biblioteca saml2 e crie as variáveis abaixo contendo o domínio, a porta e o diretório de certificados de sua aplicação.
```python
import saml2
import saml2.saml

DOMAIN = "site.exemplo.com.br"
PORT = "8080"
FQDN = "http://"+DOMAIN+":"+PORT
CERT_DIR = "certificates"

```
Inclua na lista `INSTALLED_APPS` a aplicação `djangosaml2`.
```python
INSTALLED_APPS = [
    #...outras aplicações
    'djangosaml2',
]
```
Edite a lista `AUTHENTICATION_BACKENDS` de modo a conter os seguintes backends:
```python
AUTHENTICATION_BACKENDS = [
    #... outros backends
    'django.contrib.auth.backends.ModelBackend', 
    'djangosaml2.backends.Saml2Backend',
]

```
Adicione as seguintes variáveis:
```python
MIDDLEWARE.append('djangosaml2.middleware.SamlSessionMiddleware')

# configurações relativas ao session cookie
SAML_SESSION_COOKIE_NAME = 'saml_session'
SESSION_COOKIE_SECURE = True

# Qualquer view que requer um usuário autenticado deve redirecionar o navegador para esta url 
LOGIN_URL = '/saml2/login/'

# Encerra a sessão quando o usuário fecha o navegador
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Tipo de binding utilizado
SAML_DEFAULT_BINDING = saml2.BINDING_HTTP_POST
SAML_IGNORE_LOGOUT_ERRORS = True

# Serviço de descoberta da cafeexpresso
SAML2_DISCO_URL = 'https://ds.exemplo.com.br/WAYF.php'

# Cria usuário Django a partir da asserção SAML caso o mesmo não exista
SAML_CREATE_UNKNOWN_USER = True

# URL para redirecionamento após a autenticação
LOGIN_REDIRECT_URL = '/users'
```

### Mapeamento de atributos

Insira o seguinte dicionário para realizar o mapeamento de atributos SAML para atributos do usuário Django, respectivamente.
```python
SAML_ATTRIBUTE_MAPPING = { 
    'eduPersonPrincipalName': ('username', ),
    'mail': ('email', ),
    'givenName': ('first_name', ),
    'sn': ('last_name', ),
}
```
Crie, no diretório raiz do projeto, o diretório `attribute-maps` n qual irá conter os esquemas para mapeamento de atributos.
```
$ mkdir attribute-maps
```
Crie dentro do diretório `attribute-maps` os seguintes arquivos com os respectivos conteudos:
- `basic.py`: [conteúdo do arquivo basic.py](https://github.com/IdentityPython/pysaml2/blob/master/example/attributemaps/basic.py).
- `saml_uri.py`: [conteúdo do arquivo saml_uri.py](https://github.com/IdentityPython/pysaml2/blob/master/example/attributemaps/saml_uri.py)

### Configurações sobre o SP SAML

> Ainda no arquivo `settings.py` faça as seguintes alterações.

- Inclua o dicionário `SAML_CONFIG` com as seguintes configurações:

```python
SAML_CONFIG = {
  # Biblioteca usada para assinatura e criptografia
  'xmlsec_binary': '/usr/bin/xmlsec1',

  'entityid': FQDN + '/saml2/metadata/',

  # Diretório contendo os esquemas de mapeamento de atributo
  'attribute_map_dir': os.path.join(BASE_DIR, 'attribute-maps'),

  'description': 'SP Implicit',
   
    #... mais configurações
}
```

- Configure a entidade SP no `SAML_CONFIG`.
```python
SAML_CONFIG = {
 
 #...outras configurações
 
 # Serviços a qual o servidor irá fornecer
 'service': {
      'sp' : {
          'name': 'Exemplo SP Django',
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
          ]
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
     }
   }
   #...outras configurações 
}
``` 
- Configure no `SAML_CONFIG` a forma de obtenção dos metadados da federação.
```python
SAML_CONFIG = {
 #...outras configurações
 
 # Indica onde os metadados podem ser encontrados
 'metadata': {
   'remote': [{"url": "https://ds.exemplo.com.br/ds-metadata.xml","cert": "null"},]
 }, 
 #...outras configurações 
}
``` 
- Habilite, no `SAML_CONFIG`, a opção de debug e inclua as configurações para assinatura e encriptação das asserções SAML.
```python
SAML_CONFIG = {
 #...outras configurações
 
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

 #...outras configurações 
}
``` 
- Por fim adicione as informações sobre a organização responsável pelo serviço e o contato ténico.

```python
SAML_CONFIG = {
 #...outras configurações
  # Descreve a pessoa responsável pelo serviço
  'contact_person': [
      {'given_name': 'Equipe',
       'sur_name': 'Equipe',
       'company': 'ACME',
       'email_address': 'local@exemplo.br',
       'contact_type': 'technical'},
      ],

  # Descreve a organização responsável pelo serviço    
  'organization': {
      'name': [('ACME', 'pt-br')],
      'display_name': [('ACME', 'pt-br')],
      'url': [('http://exemplo.com.br', 'pt-br')],
    },
}
``` 
## Editando de mapeamentos de URL
> As edições a seguir devem ser feitas no arquivo `url.py` do projeto.

```python
from django.urls import path, include

urlpatterns = [ 
    #... outros caminhos
    path(r'saml2/', include('djangosaml2.urls'))
]
```
## Protegendo uma aplicação com autenticação SAML

Para proteger um *endpoint* com autenticação SAML insira a anotação `@login_required` na definição da *view* da aplicação (`[dir-app]/views.py`). 
No exemplo abaixo o *endpoint* `/users` requer autenticação SAML.

```python
@login_required
def users(request):
    template = loader.get_template('base/users.html')
    meta = request.META
    return HttpResponse(template.render(meta, request))

```
## Execução da aplicação exemplo.
A aplicação utiliza o servidor Web Python padrão. Para execução da aplicação utilize o seguinte comando:
```console
$ python manage.py runserver 0:8080
```

## Endpoints da aplicação
A lista abaixo contém os principais *endpoints* configurados na aplicação.
- `/`: página inicial da aplicação contendo botão para login institucional.
- `/saml2/login/`: *endpoint* para realização de login. Os *endpoints* protegidos com autenticação SAML serão redirecionados para essa URL.
- `/saml2/metadata`: *endpoint* para o metadado do SP.
- `/users`: *endpoint* protegido com autenticação SAML. Apresenta em tela os atributos obtidos do IdP.


## Erros mapeados

### no such table: django_session

Página de erro:

```
OperationalError at /saml2/login/
no such table: django_session

Request Method: 	GET
Django Version: 	3.0.6
Exception Type: 	OperationalError
Exception Value: 	
no such table: django_session
```

Solução:

```
python manage.py makemigrations
python manage.py migrate
```
