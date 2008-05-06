PROGRAM my_plugin
        CHARACTER(80) arg
        CHARACTER(80) ssid
        CHARACTER(80) bssid
        INTEGER(4) arg_len
        INTEGER(4) errnum

        do i=1, IPXFARGC(), 1
                CALL PXFGETARG(i, arg, arg_len, errnum)
                if(arg == '-b') then
                        CALL PXFGETARG(i+1, arg, arg_len, errnum)
                        bssid=arg
                endif
                if(arg == '-s') then
                        CALL PXFGETARG(i+1, arg, arg_len, errnum)
                        ssid=arg
                endif
        end do

        print *, 'EXAMPLE PLUGIN GOT ARGUMENTS:'
        print *, 'bssid: ', bssid
        print *, 'ssid: ', ssid
END PROGRAM
