# ===-----------------------------------------------------------------------===
# @memoizable function decorator for memoizing function calls
# 
# Copyright (C) 2011: Lorenzo Martignoni <martignlo@gmail.com>
# 
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 3 of the License, or (at your option) any later
# version.  
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51
# Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
# ===-----------------------------------------------------------------------===

import inspect, hashlib, pickle, lockfile, shelve

__cache_size__ = 4096

# ===-----------------------------------------------------------------------===
# Get the mapping of arguments to values (stolen from the inspect module of
# python 2.7)
# ===-----------------------------------------------------------------------===
def getcallargs(func, *positional, **named):
    args, varargs, varkw, defaults = inspect.getargspec(func)
    f_name = func.__name__
    arg2value = {}

    # The following closures are basically because of tuple parameter
    # unpacking.
    assigned_tuple_params = []
    def assign(arg, value):
        if isinstance(arg, str):
            arg2value[arg] = value
        else:
            assigned_tuple_params.append(arg)
            value = iter(value)
            for i, subarg in enumerate(arg):
                try:
                    subvalue = next(value)
                except StopIteration:
                    raise ValueError('need more than %d %s to unpack' %
                                     (i, 'values' if i > 1 else 'value'))
                assign(subarg,subvalue)
            try:
                next(value)
            except StopIteration:
                pass
            else:
                raise ValueError('too many values to unpack')
    def is_assigned(arg):
        if isinstance(arg,str):
            return arg in arg2value
        return arg in assigned_tuple_params
    if inspect.ismethod(func) and func.im_self is not None:
        # implicit 'self' (or 'cls' for classmethods) argument
        positional = (func.im_self,) + positional
    num_pos = len(positional)
    num_total = num_pos + len(named)
    num_args = len(args)
    num_defaults = len(defaults) if defaults else 0
    for arg, value in zip(args, positional):
        assign(arg, value)
    if varargs:
        if num_pos > num_args:
            assign(varargs, positional[-(num_pos-num_args):])
        else:
            assign(varargs, ())
    elif 0 < num_args < num_pos:
        raise TypeError('%s() takes %s %d %s (%d given)' % (
            f_name, 'at most' if defaults else 'exactly', num_args,
            'arguments' if num_args > 1 else 'argument', num_total))
    elif num_args == 0 and num_total:
        raise TypeError('%s() takes no arguments (%d given)' %
                        (f_name, num_total))
    for arg in args:
        if isinstance(arg, str) and arg in named:
            if is_assigned(arg):
                raise TypeError("%s() got multiple values for keyword "
                                "argument '%s'" % (f_name, arg))
            else:
                assign(arg, named.pop(arg))
    if defaults:    # fill in any missing values with the defaults
        for arg, value in zip(args[-num_defaults:], defaults):
            if not is_assigned(arg):
                assign(arg, value)
    if varkw:
        assign(varkw, named)
    elif named:
        unexpected = next(iter(named))
        if isinstance(unexpected, unicode):
            unexpected = unexpected.encode(sys.getdefaultencoding(), 'replace')
        raise TypeError("%s() got an unexpected keyword argument '%s'" %
                        (f_name, unexpected))
    unassigned = num_args - len([arg for arg in args if is_assigned(arg)])
    if unassigned:
        num_required = num_args - num_defaults
        raise TypeError('%s() takes %s %d %s (%d given)' % (
            f_name, 'at least' if defaults else 'exactly', num_required,
            'arguments' if num_required > 1 else 'argument', num_total))
    return arg2value


# ===-----------------------------------------------------------------------===
# Return the arguments of a particular function call (default arguments are
# automatically expanded)
# ===-----------------------------------------------------------------------===
def canonicalize_args(func, *args, **kwargs):        
    # Expand all the arguments of the function 
    argsvalue = __getcallargs(func, *args, **kwargs)
    return argsvalue


# ===-----------------------------------------------------------------------===
# Return the hash of the arguments of a particular function call
# ===-----------------------------------------------------------------------===
def hash_args(func, *args, **kwargs):
    canonargs = canonicalize_args(func, *args, **kwargs)
    # Compute the md5 of the arguments (we serialize everything before to
    # obtain something that is hashable)
    canonargs = pickle.dumps(canonargs)
    hashedargs = hashlib.md5(canonargs).digest()
    del canonargs
    return hashedargs


# ===-----------------------------------------------------------------------===
# Decorator for memoization
# ===-----------------------------------------------------------------------===
def memoizable(func):
    cache = {}

    # ===-------------------------------------------------------------------===
    # Return a wrapper function that applies memoization
    # ===-------------------------------------------------------------------===
    def memoizable_func(*args, **kwargs):
        if len(cache) > __cache_size__:
            cache.clear()

        hashedargs = hash_args(func, *args, **kwargs)

        try:
            retval = cache[hashedargs]
        except KeyError:
            retval = func(*args, **kwargs)
            cache[hashedargs] = retval

        return retval

    return memoizable_func


# ===-----------------------------------------------------------------------===
# Decorator for memoization (using on disk cache)
# ===-----------------------------------------------------------------------===
def memoizable_disk(func):
    cachefile = "/tmp/%.16x.cache" % hash(func.func_code)

    # ===-------------------------------------------------------------------===
    # Return a wrapper function that applies memoization
    # ===-------------------------------------------------------------------===
    def memoizable_func(*args, **kwargs):
        lock = lockfile.FileLock(cachefile)
        lock.acquire(timeout = 15)

        cache = shelve.open(cachefile)

        if len(cache) > __cache_size__:
            cache.clear()

        hashedargs = hash_args(func, *args, **kwargs)

        try:
            retval = cache[hashedargs]
        except KeyError:
            retval = func(*args, **kwargs)
            cache[hashedargs] = retval
            
        cache.close()

        lock.release()

        return retval

    return memoizable_func


# ===-----------------------------------------------------------------------===
# Check if the 'inspect' module is recent enough (>= 2.7). If not, fallback to
# builtin 'getcallargs' (stolen from python 2.7)
# ===-----------------------------------------------------------------------===
if hasattr(inspect, "getcallargs"):
    __getcallargs = inspect.getcallargs
else:
    __getcallargs = getcallargs


if __name__ == "__main__":
    @memoizable
    def test1(a, b, c = 0):
        print "test1", a, b, c
        return a + b + c

    @memoizable
    def test2(a, b, c = 0):
        print "test2", a, b, c
        return a * b * c

    print test1(10, 10)
    print test2(10, 10)
    print test1(10, 10, 0)
    print test1(10, 10, 1)
    print test2(10, 10, 0)
    print test2(10, 10, 1)
