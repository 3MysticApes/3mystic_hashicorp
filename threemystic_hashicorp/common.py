from threemystic_hashicorp.base_class.base_common import base


class hashi_common(base): 
  """This is a common set of methods and libraries"""

  def __init__(self, *args, **kwargs) -> None:
    super().__init__(logger_name= f"hashi", *args, **kwargs)
  
  
  def vault(self, unset = False, *args, **kwargs):
    if(unset):
      self._unset("_hashi_vault")
      return
    
    if hasattr(self, "_hashi_vault"):
      return self._hashi_vault
    
    from threemystic_hashicorp.domain.vault import hashi_vault as hashi
    self._hashi_vault = hashi(
      main_reference= self, *args, **kwargs
    )
    return self.vault(*args, **kwargs)
  