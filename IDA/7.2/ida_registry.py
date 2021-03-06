# This file was automatically generated by SWIG (http://www.swig.org).
# Version 2.0.12
#
# Do not make changes to this file unless you know what you are doing--modify
# the SWIG interface file instead.




"""
IDA Plugin SDK API wrapper: registry
"""


from sys import version_info
if version_info >= (2,6,0):
    def swig_import_helper():
        from os.path import dirname
        import imp
        fp = None
        try:
            fp, pathname, description = imp.find_module('_ida_registry', [dirname(__file__)])
        except ImportError:
            import _ida_registry
            return _ida_registry
        if fp is not None:
            try:
                _mod = imp.load_module('_ida_registry', fp, pathname, description)
            finally:
                fp.close()
            return _mod
    _ida_registry = swig_import_helper()
    del swig_import_helper
else:
    import _ida_registry
del version_info
try:
    _swig_property = property
except NameError:
    pass # Python < 2.2 doesn't have 'property'.
def _swig_setattr_nondynamic(self,class_type,name,value,static=1):
    if (name == "thisown"): return self.this.own(value)
    if (name == "this"):
        if type(value).__name__ == 'SwigPyObject':
            self.__dict__[name] = value
            return
    method = class_type.__swig_setmethods__.get(name,None)
    if method: return method(self,value)
    if (not static):
        self.__dict__[name] = value
    else:
        raise AttributeError("You cannot add attributes to %s" % self)

def _swig_setattr(self,class_type,name,value):
    return _swig_setattr_nondynamic(self,class_type,name,value,0)

def _swig_getattr(self,class_type,name):
    if (name == "thisown"): return self.this.own()
    method = class_type.__swig_getmethods__.get(name,None)
    if method: return method(self)
    raise AttributeError(name)

def _swig_repr(self):
    try: strthis = "proxy of " + self.this.__repr__()
    except: strthis = ""
    return "<%s.%s; %s >" % (self.__class__.__module__, self.__class__.__name__, strthis,)

try:
    _object = object
    _newclass = 1
except AttributeError:
    class _object : pass
    _newclass = 0


def _swig_setattr_nondynamic_method(set):
    def set_attr(self,name,value):
        if (name == "thisown"): return self.this.own(value)
        if hasattr(self,name) or (name == "this"):
            set(self,name,value)
        else:
            raise AttributeError("You cannot add attributes to %s" % self)
    return set_attr


try:
    import weakref
    weakref_proxy = weakref.proxy
except:
    weakref_proxy = lambda x: x


import ida_idaapi

import sys
_BC695 = sys.modules["__main__"].IDAPYTHON_COMPAT_695_API

if _BC695:






    def bc695redef(func):
        ida_idaapi._BC695.replace_fun(func)
        return func


def reg_read_string(*args):
  """
  reg_read_string(name, subkey=None, _def=None) -> PyObject *


  Read a string from the registry.
  
  @param name: value name (C++: const char *)
  @param subkey: key name (C++: const char *)
  @return: success
  """
  return _ida_registry.reg_read_string(*args)

def reg_data_type(*args):
  """
  reg_data_type(name, subkey=None) -> regval_type_t


  Get data type of a given value.
  
  @param name: value name (C++: const char *)
  @param subkey: key name (C++: const char *)
  @return: false if the [key+]value doesn't exist
  """
  return _ida_registry.reg_data_type(*args)

def reg_read_binary(*args):
  """
  reg_read_binary(name, subkey=None) -> PyObject *


  Read binary data from the registry.
  
  @param name: value name (C++: const char *)
  @param subkey: key name (C++: const char *)
  @return: false if 'data' is not large enough to hold all data present.
           in this case 'data' is left untouched.
  """
  return _ida_registry.reg_read_binary(*args)

def reg_write_binary(*args):
  """
  reg_write_binary(name, py_bytes, subkey=None)


  Write binary data to the registry.
  
  @param name: value name (C++: const char *)
  @param subkey: key name (C++: const char *)
  """
  return _ida_registry.reg_write_binary(*args)

def reg_subkey_subkeys(*args):
  """
  reg_subkey_subkeys(name) -> PyObject *


  Get all subkey names of given key.
  
  
  @param name (C++: const char *)
  """
  return _ida_registry.reg_subkey_subkeys(*args)

def reg_subkey_values(*args):
  """
  reg_subkey_values(name) -> PyObject *


  Get all value names under given key.
  
  
  @param name (C++: const char *)
  """
  return _ida_registry.reg_subkey_values(*args)
ROOT_KEY_NAME = _ida_registry.ROOT_KEY_NAME
"""
Key used to store IDA settings in registry (Windows version).this name
is automatically prepended to all key names passed to functions in
this file.
"""
reg_unknown = _ida_registry.reg_unknown
reg_sz = _ida_registry.reg_sz
reg_binary = _ida_registry.reg_binary
reg_dword = _ida_registry.reg_dword

def reg_delete_subkey(*args):
  """
  reg_delete_subkey(name) -> bool


  Delete a key from the registry.
  
  
  @param name (C++: const char *)
  """
  return _ida_registry.reg_delete_subkey(*args)

def reg_delete_tree(*args):
  """
  reg_delete_tree(name) -> bool


  Delete a subtree from the registry.
  
  
  @param name (C++: const char *)
  """
  return _ida_registry.reg_delete_tree(*args)

def reg_delete(*args):
  """
  reg_delete(name, subkey=None) -> bool


  Delete a value from the registry.
  
  @param name: value name (C++: const char *)
  @param subkey: parent key (C++: const char *)
  @return: success
  """
  return _ida_registry.reg_delete(*args)

def reg_subkey_exists(*args):
  """
  reg_subkey_exists(name) -> bool


  Is there already a key with the given name?
  
  
  @param name (C++: const char *)
  """
  return _ida_registry.reg_subkey_exists(*args)

def reg_exists(*args):
  """
  reg_exists(name, subkey=None) -> bool


  Is there already a value with the given name?
  
  @param name: value name (C++: const char *)
  @param subkey: parent key (C++: const char *)
  """
  return _ida_registry.reg_exists(*args)

def reg_read_strlist(*args):
  """
  reg_read_strlist(list, subkey)


  Retrieve all string values associated with the given key. Also see
  'reg_update_strlist()' .
  
  @param list (C++: qstrvec_t  *)
  @param subkey (C++: const char *)
  """
  return _ida_registry.reg_read_strlist(*args)

def reg_update_strlist(*args):
  """
  reg_update_strlist(subkey, add, maxrecs, rem=None, ignorecase=False)


  Update list of strings associated with given key.
  
  @param subkey: key name (C++: const char *)
  @param add: string to be added to list, can be NULL (C++: const char
              *)
  @param maxrecs: limit list to this size (C++: size_t)
  @param rem: string to be removed from list, can be NULL (C++: const
              char *)
  @param ignorecase: ignore case for 'add' and 'rem' (C++: bool)
  """
  return _ida_registry.reg_update_strlist(*args)

def reg_write_string(*args):
  """
  reg_write_string(name, utf8, subkey=None)


  Write a string to the registry.
  
  @param name: value name (C++: const char *)
  @param utf8: utf8-encoded string (C++: const char *)
  @param subkey: key name (C++: const char *)
  """
  return _ida_registry.reg_write_string(*args)

def reg_read_int(*args):
  """
  reg_read_int(name, defval, subkey=None) -> int


  Read integer value from the registry.
  
  @param name: value name (C++: const char *)
  @param defval: default value (C++: int)
  @param subkey: key name (C++: const char *)
  @return: the value read from the registry, or 'defval' if the read
           failed
  """
  return _ida_registry.reg_read_int(*args)

def reg_write_int(*args):
  """
  reg_write_int(name, value, subkey=None)


  Write integer value to the registry.
  
  @param name: value name (C++: const char *)
  @param value: value to write (C++: int)
  @param subkey: key name (C++: const char *)
  """
  return _ida_registry.reg_write_int(*args)

def reg_read_bool(*args):
  """
  reg_read_bool(name, defval, subkey=None) -> bool


  Read boolean value from the registry.
  
  @param name: value name (C++: const char *)
  @param defval: default value (C++: bool)
  @param subkey: key name (C++: const char *)
  @return: boolean read from registry, or 'defval' if the read failed
  """
  return _ida_registry.reg_read_bool(*args)

def reg_write_bool(*args):
  """
  reg_write_bool(name, value, subkey=None)


  Write boolean value to the registry.
  
  @param name: value name (C++: const char *)
  @param value: boolean to write (nonzero = true) (C++: int)
  @param subkey: key name (C++: const char *)
  """
  return _ida_registry.reg_write_bool(*args)

def reg_update_filestrlist(*args):
  """
  reg_update_filestrlist(subkey, add, maxrecs, rem=None)


  Update registry with a file list. Case sensitivity will vary depending
  on the target OS.'add' and 'rem' must be UTF-8, just like for regular
  string operations.
  
  @param subkey (C++: const char *)
  @param add (C++: const char *)
  @param maxrecs (C++: size_t)
  @param rem (C++: const char *)
  """
  return _ida_registry.reg_update_filestrlist(*args)

def reg_load(*args):
  """
  reg_load()
  """
  return _ida_registry.reg_load(*args)

def reg_flush(*args):
  """
  reg_flush()
  """
  return _ida_registry.reg_flush(*args)

