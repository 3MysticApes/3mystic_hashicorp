import hvac as hasicorp_hvac
import boto3, os
from threemystic_common.base_class.base_common import base

# WARNING: This will probably be moved to its own stand alone project.
class hashi_vault(base): 
  """This is a set of library wrappers to help monitor performance"""

  def __init__(self, version = 2, *args, **kwargs) -> None:
    super().__init__(logger_name= f"hashi_vault", *args, **kwargs)
    self.version = version
    
  
  def isauthenticated(self, client:hasicorp_hvac.Client=None, *args, **kwargs):   
    try:
      return self._get_client(client= client).is_authenticated()
    except Exception:
      return False
    
  def _get_client(self, client = None)->hasicorp_hvac.Client: 
    if client is not None:
      return client
    if self.client is None:
      raise Exception("Please generate a client or call generate_client first")
      return
    
    return self.client
  
  def _get_secrets_version(self, client = None): 
    if self.version == 2:
      return self._get_client(client= client).secrets.kv.v2
    
    return self._get_client(client= client).secrets.kv.v1

  def generate_client(self, *args, **kwargs):
    self.client = hasicorp_hvac.Client(*args, **kwargs)

  def __authenticate_get_credentials_ec2(self, metadata_url_base='http://169.254.169.254'):
    import requests

    iam_role_request = requests.get(url=f'{metadata_url_base}/latest/meta-data/iam/security-credentials')
    iam_role_request.raise_for_status()
    role_name = iam_role_request.text
    
    metadata_pkcs7_url = f'{metadata_url_base}/latest/meta-data/iam/security-credentials/{role_name}'
    self.get_logger().debug("load_aws_ec2_role_iam_credentials connecting to %s" % metadata_pkcs7_url)
    response = requests.get(url=metadata_pkcs7_url)
    response.raise_for_status()
    security_credentials = response.json()
    return security_credentials
  
  def __authenticate_get_credentials(self, pull_ec2_meta):
    if pull_ec2_meta:
      return self.__authenticate_get_credentials_ec2()

    
    session = boto3.Session()
    credentials = session.get_credentials()
    return {
      "AccessKeyId" : credentials.access_key,
      "SecretAccessKey" : credentials.secret_key,
      "Token" : credentials.token
    }

  def __authenticate_aws_iam(self, client:hasicorp_hvac.Client=None, data = None, mount_point = "aws", pull_ec2_meta = False, *args, **kwargs):
    default_iam_auth_creds = {
      "mount_point": mount_point
    }
    if data is not None and not self.get_common().isNullOrWhiteSpace(data.get("vault_role")):
      default_iam_auth_creds["role"] = data.get("vault_role")    
    

    if data is not None and data.get("auth_data") is not None:
      try:
        self._get_client(client= client).auth.aws.iam_login(**self.get_common().merge_dictionary([{}, default_iam_auth_creds, data.get("auth_data")]))
        return
      except Exception as ex:
        self.get_logger().exception(msg= str(ex), exc_info= ex)
        self.get_logger().exception(msg= str(ex), exc_info= ex)
        return
    
    try:
      self._get_client(client= client).auth.aws.iam_login(**self.get_common().merge_dictionary([{}, default_iam_auth_creds, self.__authenticate_get_credentials(pull_ec2_meta= pull_ec2_meta)]))
      return
    except Exception as ex_session:
      try:
        if not self.get_common().isNullOrWhiteSpace(os.environ.get("AWS_ACCESS_KEY_ID")) and not pull_ec2_meta:
          self._get_client(client= client).auth.aws.iam_login(**self.get_common().merge_dictionary([{}, default_iam_auth_creds, {
            "access_key": os.environ.get("AWS_ACCESS_KEY_ID"),
            "secret_key": os.environ.get("AWS_SECRET_ACCESS_KEY"),
            "session_token": os.environ.get("AWS_SESSION_TOKEN")
          }]))
        return
      except Exception as ex_environ:
        self.get_logger().exception(msg= str(ex_session), exc_info= ex_session)
        self.get_logger().exception(msg= str(ex_environ), exc_info= ex_environ)
    
    

    raise Exception("Could not Authenticate aws iam")

  def authenticate(self, login_type, client:hasicorp_hvac.Client=None, data = None, *args, **kwargs):
    if login_type.lower() == "token":   
      self._get_client(client= client).token = data.get("token")
      return
    
    if login_type.lower() == "aws_iam":   
      self.__authenticate_aws_iam(login_type=login_type, client= client, data = data, *args, **kwargs)
      return

    if login_type.lower() == "ldap":    
      from getpass import getpass  
      self._get_client(client= client).auth.ldap.login(
        username=input('LDAP Username:'),
        password=getpass('LDAP Password:')
      )
      return
  
  def create_update_secret(self, secret_path, secret, client = None, *args, **kwargs):
    return self._get_secrets_version(client= client).create_or_update_secret(
      path= secret_path,
      secret= secret
    )

  def patch_secret_keyvalue(self, secret_path, secret_key, secret_value, client = None, *args, **kwargs):
    if self.version < 2:
      raise Exception("PatchNotSupported")
    
    return self._get_secrets_version(client= client).patch(
      path= secret_path,
      secret= {
        secret_key:secret_value
      }
    )

  def patch_secret(self, secret_path, secret, client = None, *args, **kwargs):
    if self.version < 2:
      raise Exception("PatchNotSupported")

    return self._get_secrets_version(client= client).patch(
      path= secret_path,
      secret= secret
    )

  def _get_secret_data(self, secret_data, secret_key = None, *args, **kwargs ):
    
    if self.get_common().isNullOrWhiteSpace(secret_key):
      return secret_data

    return secret_data.get(secret_key)

  def get_secret_data(self, secret_path, version = None, secret_key = None, client = None, *args, **kwargs):
    secret_data = self.get_secret(secret_path= secret_path, version = version, client = client, *args, **kwargs)

    data = secret_data.get("data")
    if data is None:
      return None
    
    if self.version >= 2:
      data = data.get("data")
    
    return self._get_secret_data(secret_data= data, secret_key= secret_key)

    

  def get_secret(self, secret_path, version = None, client = None, *args, **kwargs):
    if version is None:
      return self._get_secrets_version(client= client).read_secret_version(
        path= secret_path,
      )
    
    if self.version < 2:
      raise Exception("SecretVersionNotSupported")
    return self._get_secrets_version(client= client).read_secret_version(
        path= secret_path,
        version= version
      )
  
  def list_secrets(self, secret_path, client = None, *args, **kwargs):
    return self._get_secrets_version(client= client).list_secrets(
        path=secret_path,
      )

  def get_secret_metadata(self, secret_path, client = None, *args, **kwargs):
    if self.version < 2:
      raise Exception("UpdatedMetaDataNotSupported")
      
    return self._get_secrets_version(client= client).read_secret_metadata(
        path=secret_path, 
        **kwargs
      )

  def update_secret_metadata(self, secret_path, client = None, *args, **kwargs):
    if self.version < 2:
      raise Exception("ReadMetaDataNotSupported")
      
    return self._get_secrets_version(client= client).update_metadata(
        path=secret_path, 
        **kwargs
      ) 

  def delete_secret_metadata_versions(self, secret_path, client = None, *args, **kwargs):
    if self.version < 2:
      raise Exception("DeleteMetaDataVersionsNotSupported")
      
    return self._get_secrets_version(client= client).delete_metadata_and_all_versions(
        path=secret_path
      )

  def delete_secret(self, secret_path, version = None, client = None, *args, **kwargs):
    if version is None:
      if self.version < 2:
        return self._get_secrets_version(client= client).delete_secret(
          path=secret_path,
        )
      
      return self._get_secrets_version(client= client).delete_latest_version_of_secret(
        path=secret_path,
      )
    
    if self.version < 2:
      raise Exception("DeleteVersionNotSupported")
    
    if not self.get_common().is_type(version, list):
      version = [version]
    return self._get_secrets_version(client= client).delete_secret_versions(
        path=secret_path,
        versions = version
      )
  
  def undelete_secret(self, secret_path, version = None, client = None, *args, **kwargs):
    if self.version < 2:
      raise Exception("DeleteVersionNotSupported")
    
    if version is None:
      hvac_path_metadata = self.get_secret_metadata(secret_path= secret_path, version= version, client= client, *args, **kwargs)
      version = [hvac_path_metadata['data']['current_version']]    
    
    
    if not self.get_common().is_type(version, list):
      version = [version]

    return self._get_secrets_version(client= client).undelete_secret_versions(
        path=secret_path,
        versions = version
      )

  def destroy_secret(self, secret_path, version = None, client = None, *args, **kwargs):
    if self.version < 2:
      return self.delete_secret(secret_path= secret_path, version= None, client= client, *args, **kwargs )
    
    if not self.get_common().is_type(version, list):
      version = [version]

    return self.read_secret_metadata(client= client).destroy_secret_versions(
        path= secret_path,
        versions= version
      )