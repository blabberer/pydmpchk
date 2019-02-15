windbg dmpchk clone                             
dumps handle info from supposedly corrupt dumps                              
(does not rely on windbg interfaces)                                                              
parses raw dump file                                   
remove the comments from code for verbose information regarding rvs               
in _MINIDUMP_DIRECTORY,HANDLE_DESCRIPTOR etc                     

usage python pydmpchk.py path_to_dump_file >> sometext.txt                 

should yield results like                 

MINIDUMP_HEADER EXCLUDING SIGNATURE                                
MINIDUMP_DIRECTORY                         
_MINIDUMP_HANDLE_DESCRIPTOR2                          
_MINIDUMP_STRING                   
Handle      TypeName        ObjectName                  
0x4         Directory       \KnownDlls                 
0x8         File            No ObjName                 
0xc         File No         ObjName                        
0x10        File            No ObjName                       
0x14        ALPC Port       No ObjName                            
0x18        Key             \REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Nls\Sorting\Versions                  
