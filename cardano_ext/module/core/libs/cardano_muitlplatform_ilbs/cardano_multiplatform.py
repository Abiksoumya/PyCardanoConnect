
import codecs
import memoryview
import numpy as np
import json
import traceback
import re
import wasmtime
import bech32




wasm = None


cached_text_decoder = codecs.getincrementaldecoder("utf-8")(errors='strict', byteorder='big')

decoded_data = cached_text_decoder.decode()

cached_unit_memory0 = None



def get_unit8_memory0():
    global cached_unit_memory0

    if cached_unit_memory0 is None or len(cached_unit_memory0) == 0:
        cached_unit_memory0 = memoryview(wasm.memory)
    return cached_unit_memory0

def get_string_from_wasm0(ptr, length):
    memory = get_unit8_memory0()
    data = memory[ptr:ptr+length].tobytes()
    decoded_string = data.decode("utf-8")
    return decoded_string

heap = [None] * 128
heap.extend([None, None, True, False])
heap_next = len(heap)

def add_heap_object(obj):
    global heap_next, heap

    if heap_next == len(heap):
        heap.append(len(heap) + 1 )

    idx = heap_next
    heap_next = heap[idx]

    heap[idx] = obj
    return idx

def get_object(idx):
    global heap
    return heap[idx]

def drop_object(idx):
    global heap, heap_next

    if idx < 132:
        return

    heap[idx] = heap_next
    heap_next = idx


def take_object(idx):
    ret = get_object(idx)
    drop_object(idx)
    return ret

WASM_VECTOR_LEN = 0

cached_text_encoder = codecs.getincrementalencoder("utf-8")()

def encode_string(arg, view):
    encoded_data, bytes_written, _ = cached_text_encoder.encode(arg, final=True)
    view[:bytes_written] = encoded_data
    return bytes_written

def pass_string_to_wasm0(arg, malloc, realloc=None):
    global WASM_VECTOR_LEN

    if realloc is None:
        buf = cached_text_encoder.encode(arg, final=True)
        ptr = malloc(len(buf))
        view = get_unit8_memory0()
        view[ptr : ptr + len(buf)] = buf
        WASM_VECTOR_LEN = len(buf)
        return ptr
    len_arg = len(arg)
    ptr = malloc(len_arg)
    mem = get_unit8_memory0()

    offset = 0

    for offset in range(len_arg):
        code = ord(arg[offset])
        if code > 0x7F:
            break
        mem[ptr + offset] = code


    if offset != len_arg:
        if offset != 0:
            arg = arg[offset:]
        ptr = realloc(ptr, len_arg, len_arg = offset + len(arg) * 3)
        view = get_unit8_memory0()[ptr + offset : ptr + len_arg]
        ret = encode_string(arg, view)
        offset += ret

    WASM_VECTOR_LEN = offset
    return ptr

cached_int32_memory0 = None

def get_int32_memory0():
    global cached_int32_memory0
    if cached_int32_memory0 is None or cached_int32_memory0.nbytes == 0:
        cached_int32_memory0 = np.array(wasm.memory.buffer, dtype=np.int32)
    return cached_int32_memory0

def is_like_none(x):
    return x is None or x is None

def debug_string(val):
    # primitive types
    val_type = type(val).__name__
    if val_type in ["int", "float", "bool"] or val is None:
        return str(val)
    if val_type == "str":
        return f'"{val}"'
    if val_type == "Symbol":
        description = val.description
        if description is None:
            return "Symbol"
        else:
            return f'Symbol({description})'
    if val_type == "function":
        name = val.__name__
        if isinstance(name, str) and len(name) > 0:
            return f'Function({name})'
        else:
            return "Function"
    # objects
    if isinstance(val, list):
        length = len(val)
        debug = "["
        if length > 0:
            debug += debug_string(val[0])
        for i in range(1, length):
            debug += ", " + debug_string(val[i])
        debug += "]"
        return debug
    # Test for built-in
    built_in_matches = re.findall(r'\[object ([^\]]+)\]', str(type(val)))
    if len(built_in_matches) > 0:
        class_name = built_in_matches[0]
    else:
        # Failed to match the standard '[object ClassName]'
        return str(type(val))
    if class_name == "Object":
        # we're a user defined class or Object
        # json.dumps avoids problems with cycles, and is generally much
        # easier than looping through properties of `val`.
        try:
            return "Object(" + json.dumps(val) + ")"
        except:
            return "Object"
    # errors
    if isinstance(val, BaseException):
        return f'{val.__class__.__name__}: {val}\n{traceback.format_exc()}'
    # TODO we could test for more things here, like `Set`s and `Map`s.
    return class_name




# finalize function start

import weakref

CLOSURE_DTORS = {}

def finalize_callback(weak_state):
    state = weak_state()
    if state is not None:
        wasm.__wbindgen_export_2.get(state['dtor'])(state['a'], state['b'])

def register_finalization(state):
    weak_state = weakref.ref(state, finalize_callback)
    CLOSURE_DTORS[weak_state] = None

def unregister_finalization(state):
    for weak_state in CLOSURE_DTORS.keys():
        if weak_state() == state:
            del CLOSURE_DTORS[weak_state]
            break


# finalize function end

def make_mut_closure(arg0, arg1, dtor, f):
    state = {"a": arg0, "b": arg1, "cnt": 1, "dtor": dtor}

    def real(*args):
        # First, with a closure, we increment the internal reference count.
        # This ensures that the Rust closure environment won't be deallocated
        # while we're invoking it.
        state["cnt"] += 1
        a = state["a"]
        state["a"] = 0

        try:
            return f(a, state["b"], *args)
        finally:
            if state["cnt"] == 0:
                wasm.__wbindgen_export_2.get(state["dtor"])(a, state["b"])
                CLOSURE_DTORS.unregister(state)
            else:
                state["a"] = a
    
    real.original = state
    CLOSURE_DTORS.register(real, state, state)


    return real





# address class
import atexit

# Define a list to keep track of the pointers that need to be freed
address_pointers = []

# Define a function to free the memory associated with the pointers
def free_addresses():
    for ptr in address_pointers:
        wasm.__wbg_address_free(ptr)

# Register the function to be called at program exit
atexit.register(free_addresses)

# When you create a new address and obtain its pointer, add it to the list
address_ptr = wasm.__wbg_get_address_ptr()
address_pointers.append(address_ptr)

# Use the address pointer as needed

# When the address is no longer needed, remove it from the list
address_pointers.remove(address_ptr)


class Address:
    def __init__(self, ptr):
        self.ptr = ptr

    def wrap_address(ptr):
        address = Address(ptr)
        # Register the address object for finalization or cleanup if needed
        # Note: The specific finalization logic would depend on your requirements
        # You would need to implement the necessary cleanup logic for the Python object
        # This could involve calling appropriate functions to free resources, close connections, etc.
        # Here, we're just printing a message for demonstration purposes
        print("Finalizing Address:", address.ptr)
        return address


    def from_bytes(data):
        try:
            store = wasmtime.Store()
            module = wasmtime.Module(store.engine, "<path_to_wasm_file>")
            instance = wasmtime.Instance(module, [])
            memory = instance.exports.get_memory("memory")

            # Allocate memory in the WebAssembly linear memory and copy the data
            ptr = memory.grow(len(data))
            memory.data_view()[ptr:ptr + len(data)] = data

            # Call the WebAssembly function
            address_from_bytes = instance.exports.get_func("address_from_bytes")
            retptr = store.externref()
            address_from_bytes(ptr, len(data), retptr)

            # Retrieve the result from WebAssembly linear memory
            result_ptr = retptr.data()
            r0 = memory.data_view()[result_ptr // 4]
            r1 = memory.data_view()[(result_ptr // 4) + 1]
            r2 = memory.data_view()[(result_ptr // 4) + 2]

            if r2:
                raise Exception(take_object(r1))  # Replace takeObject with the appropriate logic

            return Address.wrap(r0)  # Replace Address.__wrap with the appropriate wrapping logic
        finally:
            # Cleanup or finalize resources if needed
            pass

    def from_bech32(bech_str):
        try:
            # Decode the Bech32 string
            hrp, data = bech32.bech32_decode(bech_str)
            
            # Convert the Bech32 data to bytes
            data_bytes = bech32.convertbits(data, len(data), 5, 8, False)
            
            # Call the necessary wasm function or handle the data accordingly
            # You would need to provide the specific logic here based on your use case

            # Return the result (assuming it is an address)
            return Address.wrap(data_bytes)  # Replace Address.__wrap with the appropriate wrapping logic
        finally:
            # Cleanup or finalize resources if needed
            pass

    def to_bech32(self, prefix):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = 0
            len0 = 0
            if prefix is not None:
                ptr0 = pass_string_to_wasm0(
                    prefix,
                    wasm.__wbindgen_malloc,
                    wasm.__wbindgen_realloc,
                )
                len0 = WASM_VECTOR_LEN
            wasm.address_to_bech32(retptr, self.ptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            r3 = get_int32_memory0()[int(retptr / 4 + 3)]
            ptr1 = r0
            len1 = r1
            if r3:
                ptr1 = 0
                len1 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr1, len1)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr1, len1)



import ctypes

# Define the callback function
def free_ed25519_key_hash(ptr):
    # Call the appropriate cleanup function
    wasm.__wbg_ed25519keyhash_free(ptr)

# Create the finalization registry
Ed25519KeyHashFinalization = ctypes.finalizer(free_ed25519_key_hash)

import ctypes
import array

class Ed25519KeyHash:
    def __init__(self, ptr):
        self.ptr = ptr
        Ed25519KeyHashFinalization.register(self, self.ptr, self)
    
    def __del__(self):
        self.free()
    
    @staticmethod
    def __wrap(ptr):
        return Ed25519KeyHash(ptr)
    
    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        Ed25519KeyHashFinalization.unregister(self)
        return ptr
    
    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_ed25519keyhash_free(ptr)
    
    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = ctypes.cast(bytes.buffer_info()[0], ctypes.c_void_p).value
            len0 = len(bytes)
            wasm.ed25519keyhash_from_bytes(retptr, ptr0, len0)
            r0 = ctypes.c_int32.from_address(retptr).value
            r1 = ctypes.c_int32.from_address(retptr + 4).value
            r2 = ctypes.c_int32.from_address(retptr + 8).value
            if r2:
                raise take_object(r1)
            return Ed25519KeyHash.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
    
    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.ed25519keyhash_to_bytes(retptr, self.ptr)
            r0 = ctypes.c_int32.from_address(retptr).value
            r1 = ctypes.c_int32.from_address(retptr + 4).value
            data = array.array("B", ctypes.string_at(r0, r1))
            wasm.__wbindgen_free(r0, r1)
            return data
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
    
    def to_bech32(self, prefix):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            prefix_bytes = prefix.encode("utf-8")
            ptr0 = ctypes.cast(prefix_bytes, ctypes.c_void_p).value
            len0 = len(prefix_bytes)
            wasm.ed25519keyhash_to_bech32(retptr, self.ptr, ptr0, len0)
            r0 = ctypes.c_int32.from_address(retptr).value
            r1 = ctypes.c_int32.from_address(retptr + 4).value
            r2 = ctypes.c_int32.from_address(retptr + 8).value
            r3 = ctypes.c_int32.from_address(retptr + 12).value
            ptr1 = r0
            len1 = r1
            if r3:
                ptr1 = 0
                len1 = 0
                raise take_object(r2)
            bech_str = ctypes.string_at(ptr1, len1).decode("utf-8")
            return bech_str
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr1, len1)

    @staticmethod
    def from_hex(hex_str):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                hex_str,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc
            )
            len0 = WASM_VECTOR_LEN
            wasm.ed25519keyhash_from_hex(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return Ed25519KeyHash.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)



# pass array function start________________________________________
def passArray8ToWasm0(arg, malloc):
    ptr = malloc(len(arg))
    get_unit8_memory0()[ptr:ptr + len(arg)] = arg
    global WASM_VECTOR_LEN
    WASM_VECTOR_LEN = len(arg)
    return ptr

# pass array function end


# get array 8
def getArrayU8FromWasm0(ptr, length):
    return get_unit8_memory0()[ptr:ptr+length]



    
def free_script_hash(ptr):
    # Call the appropriate cleanup function
    wasm.__wbg_scripthash_free(ptr)

# Create the finalization registry
ScriptHashFinalization = ctypes.finalizer(free_script_hash)    


class ScriptHash:
    def __init__(self, ptr):
        self.ptr = ptr
        ScriptHashFinalization.register(self, self.ptr, self)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        ScriptHashFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_scripthash_free(ptr)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.scripthash_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4) + 0]
            r1 = get_int32_memory0()[int(retptr / 4) + 1]
            r2 = get_int32_memory0()[int(retptr / 4) + 2]
            if r2:
                raise take_object(r1)
            return ScriptHash.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.ed25519keyhash_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4) + 0]
            r1 = get_int32_memory0()[int(retptr / 4) + 1]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_bech32(self, prefix):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                prefix,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc,
            )
            len0 = WASM_VECTOR_LEN
            wasm.ed25519keyhash_to_bech32(retptr, self.ptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4) + 0]
            r1 = get_int32_memory0()[int(retptr / 4) + 1]
            r2 = get_int32_memory0()[int(retptr / 4) + 2]
            r3 = get_int32_memory0()[int(retptr / 4) + 3]
            ptr1 = r0
            len1 = r1
            if r3:
                ptr1 = 0
                len1 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr1, len1)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr1, len1)

    @staticmethod
    def from_hex(hex_str):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = pass_string_to_wasm0(
                hex_str,
                wasm.__wbindgen_malloc,
                wasm.__wbindgen_realloc
            )
            len0 = WASM_VECTOR_LEN
            wasm.scripthash_from_hex(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return ScriptHash.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)


   




import weakref


class FinalizationRegistry:
    def __init__(self, cleanup_fn):
        self.cleanup_fn = cleanup_fn
        self.refs = weakref.WeakValueDictionary()

    def register(self, obj, ptr):
        self.refs[ptr] = obj

    def unregister(self, ptr):
        if ptr in self.refs:
            del self.refs[ptr]

    def cleanup(self):
        for ptr in self.refs.keys():
            self.cleanup_fn(ptr)

# asseret class__________________________________________________________________
def _assertClass(instance, klass):
    if not isinstance(instance, klass):
        raise ValueError(f"expected instance of {klass.__name__}")
    return instance.ptr
# _______________________________________________________________________________

class StakeCredential:
    def __init__(self, ptr):
        self.ptr = ptr
        FinalizationRegistry.register(self, self.ptr)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        FinalizationRegistry.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_stakecredential_free(ptr)

    @staticmethod
    def from_keyhash(hash):
        _assertClass(hash, Ed25519KeyHash)
        ret = wasm.stakecredential_from_keyhash(hash.ptr)
        return StakeCredential(ret)

    @staticmethod
    def from_scripthash(hash):
        _assertClass(hash, ScriptHash)
        ret = wasm.stakecredential_from_scripthash(hash.ptr)
        return StakeCredential(ret)

    def to_keyhash(self):
        ret = wasm.stakecredential_to_keyhash(self.ptr)
        return None if ret == 0 else Ed25519KeyHash(ret)

    def to_scripthash(self):
        ret = wasm.stakecredential_to_scripthash(self.ptr)
        return None if ret == 0 else ScriptHash(ret)

    def kind(self):
        ret = wasm.language_kind(self.ptr)
        return ret 

    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.stakecredential_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.stakecredential_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            if r2:
                raise take_object(r1)
            return StakeCredential(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    def to_json(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.stakecredential_to_json(retptr, self.ptr)
            r0 = get_int32_memory0()[retptr // 4 + 0]
            r1 = get_int32_memory0()[retptr // 4 + 1]
            r2 = get_int32_memory0()[retptr // 4 + 2]
            r3 = get_int32_memory0()[retptr // 4 + 3]
            ptr0 = r0
            len0 = r1
            if r3:
                ptr0 = 0
                len0 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr0, len0)
        finally:
            wasm





class BaseAddress:
    def __init__(self,ptr):
        self.ptr = ptr
        FinalizationRegistry.register(self, self.ptr, self)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        FinalizationRegistry.unregister(self)
        return ptr
    
    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_baseaddress_free(ptr)

    @staticmethod
    def __wrap(ptr):
        obj = BaseAddress(ptr)
        return obj
    
    @staticmethod
    def new(network, payment, stake):
        _assertClass(payment, StakeCredential)
        _assertClass(stake, StakeCredential)
        ret = wasm.baseaddress_new(network, payment.ptr, stake.ptr)
        return BaseAddress.__wrap(ret)
    
    def payment_cred(self):
        ret = wasm.baseaddress_payment_cred(self.ptr)
        return StakeCredential.__wrap(ret)
    
    def stake_cred(self):
        ret = wasm.baseaddress_stake_cred(self.ptr)
        return StakeCredential.__wrap(ret)
    
    def to_address(self):
        ret = wasm.baseaddress_to_address(self.ptr)
        return Address.__wrap(ret)
    
    @staticmethod
    def from_address(addr):
        _assertClass(addr, Address)
        ret = wasm.address_as_base(addr.ptr)
        return BaseAddress.__wrap(ret) if ret != 0 else None
    



# EnterPrice Address 

class EnterpriseAddressFinalization:
    def __init__(self, ptr):
        self.ptr = ptr
        self.finalizer = weakref.finalize(self, wasm.__wbg_enterpriseaddress_free, ptr)



class EnterpriseAddress:
    def __init__(self, ptr):
        self.ptr = ptr
        EnterpriseAddressFinalization.register(self, self.ptr, self)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        EnterpriseAddressFinalization.unregister(self)
        return ptr

    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_enterpriseaddress_free(ptr)

    @staticmethod
    def new(network, payment):
        _assertClass(payment, StakeCredential)
        ret = wasm.enterpriseaddress_new(network, payment.ptr)
        return EnterpriseAddress(ret)

    def payment_cred(self):
        ret = wasm.baseaddress_payment_cred(self.ptr)
        return StakeCredential(ret)

    def to_address(self):
        ret = wasm.enterpriseaddress_to_address(self.ptr)
        return Address(ret)

    @staticmethod
    def from_address(addr):
        _assertClass(addr, Address)
        ret = wasm.address_as_enterprise(addr.ptr)
        return EnterpriseAddress(ret)
    



# Rewarded Address
class RewardAddressesFinalization:
    def __init__(self, cleanup_fn):
        self.cleanup_fn = cleanup_fn
        self.refs = weakref.WeakValueDictionary()

    def register(self, obj, ptr):
        self.refs[ptr] = obj

    def unregister(self, ptr):
        if ptr in self.refs:
            del self.refs[ptr]

    def cleanup(self):
        for ptr in self.refs.keys():
            self.cleanup_fn(ptr)

    



class RewardAddresses:
    def __init__(self, ptr):
        self.ptr = ptr
        RewardAddressesFinalization.register(self, self.ptr, self)

    def __destroy_into_raw(self):
        ptr = self.ptr
        self.ptr = 0
        RewardAddressesFinalization.unregister(self)
        return ptr
    
    def free(self):
        ptr = self.__destroy_into_raw()
        wasm.__wbg_rewardaddresses_free(ptr)

    @staticmethod
    def __wrap(ptr):
        obj = RewardAddresses(ptr)
        return obj


    def to_bytes(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.rewardaddresses_to_bytes(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            v0 = getArrayU8FromWasm0(r0, r1).copy()
            wasm.__wbindgen_free(r0, r1 * 1)
            return v0
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
    
    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.rewardaddresses_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return RewardAddresses.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)

    @staticmethod
    def from_bytes(bytes):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc)
            len0 = WASM_VECTOR_LEN
            wasm.rewardaddresses_from_bytes(retptr, ptr0, len0)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return RewardAddresses.__wrap(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)


    def to_json(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.rewardaddresses_to_json(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            r3 = get_int32_memory0()[int(retptr / 4 + 3)]
            ptr0 = r0
            len0 = r1
            if r3:
                ptr0 = 0
                len0 = 0
                raise take_object(r2)
            return get_string_from_wasm0(ptr0, len0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)
            wasm.__wbindgen_free(ptr0, len0)

    def to_js_value(self):
        try:
            retptr = wasm.__wbindgen_add_to_stack_pointer(-16)
            wasm.rewardaddresses_to_js_value(retptr, self.ptr)
            r0 = get_int32_memory0()[int(retptr / 4 + 0)]
            r1 = get_int32_memory0()[int(retptr / 4 + 1)]
            r2 = get_int32_memory0()[int(retptr / 4 + 2)]
            if r2:
                raise take_object(r1)
            return take_object(r0)
        finally:
            wasm.__wbindgen_add_to_stack_pointer(16)




















