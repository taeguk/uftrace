#
# gdb helper commands and functions for uftrace debugging
# copied from the Linux kernel source
#
#  module tools
#
# Copyright (c) Siemens AG, 2013
#
# Authors:
#  Jan Kiszka <jan.kiszka@siemens.com>
#
# This work is licensed under the terms of the GNU GPL version 2.
#

import gdb
import os
from uftrace import utils, lists


plthook_data_type = utils.CachedType("struct plthook_data")


def plthook_list():
    global module_type
    plthook_modules = utils.gdb_eval_or_none("plthook_modules")
    if plthook_modules is None:
        return

    pd_ptr_type = plthook_data_type.get_type().pointer()

    for module in lists.list_for_each_entry(plthook_modules, pd_ptr_type, "list"):
        yield module


def find_module_by_name(name):
    for module in plthook_list():
        if os.path.basename(module['mod_name'].string()) == name:
            return module
    return None


class UftPltModule(gdb.Function):
    """Find plthook module by name and return the module variable.

$uft_module("MODULE"): Given the name MODULE, iterate over all loaded modules
of the target and return that module variable which MODULE matches."""

    def __init__(self):
        super(UftPltModule, self).__init__("uft-plt-module")

    def invoke(self, mod_name):
        mod_name = mod_name.string()
        module = find_module_by_name(mod_name)
        if module:
            return module.dereference()
        else:
            raise gdb.GdbError("Unable to find MODULE " + mod_name)


UftPltModule()


class UftPltList(gdb.Command):
    """List currently loaded plthook modules."""

    def __init__(self):
        super(UftPltList, self).__init__("uft-plt-list", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        gdb.write("{id:>16}  {addr:>16}  {name:<32}\n".format(
            id="Module Id", name="Name", addr="Base Address"))

        for module in plthook_list():
            gdb.write("{id:>16}  {addr:>16}  {name:<32}\n".format(
                id=hex(module['module_id']),
                addr=hex(module['base_addr']),
                name=os.path.basename(module['mod_name'].string())))


UftPltList()
