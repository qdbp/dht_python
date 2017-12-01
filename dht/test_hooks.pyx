from bdecode_st cimport parsed_msg, krpc_bdecode, print_parsed_msg, g_trace
from bdecode_st cimport bd_status, bd_status_names

cpdef show_bdecode(bytes b):

    cdef parsed_msg output
    cdef bd_status status = krpc_bdecode(b, &output)

    if status == bd_status.NO_ERROR:
        print_parsed_msg(&output)

    return bd_status_names[status]

cpdef print_trace():
    print('\n'.join(g_trace))
