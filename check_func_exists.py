import sys
sys.path.append('/home/nuc/Desktop/VIVA/')
from extract_callchain_from_sourcecode.no_inline import structurize_cve
import subprocess 
import pandas as pd
import os
from pdb import set_trace as bp

#Check whether all the binaries contain the vulnerable function.
def check_func_exist():
 xml_path=input("Please enter the cve.xml path:").strip("'")
 sheet_name=input("Please enter the sheet name:")
 df=pd.read_excel(xml_path, sheet_name)
 cve_index=list(filter(None, df["CVE"]))
 file_path=list(filter(None, df["File Path"]))
 last_versions=list(filter(None, df["Last"]))
 funcs=list(filter(None, df["Function Name"]))

 all_versions_record=input("Please enter the path recording all versions:").strip("'")
 f=open(all_versions_record,"r")
 descending_versions=list(filter(None,f.read().split("\n")))
 
 all_compiled_versions_path=input("Please enter the path compiling all versions:").strip("'")
 #Now structure information for each cve 
 structured_cve_list=structurize_cve(cve_index,file_path,last_versions,descending_versions,all_compiled_versions_path,funcs)
 
 cve_dir=input("PLease enter the folder recording all cves:").strip("'")
 
 #Now copy paste bin files for each cve
 for cve in structured_cve_list:
  #print("cve=",cve.cve_index,cve.last_vulnerable_version,cve.first_patched_version,cve.vul_bins)
  check_cve(cve,all_compiled_versions_path,cve_dir)

#Check a cve.
def check_cve(cve,all_compiled_versions_path,cve_dir):
  for path in cve.vul_bins:
   for bin_name in cve.vul_bins[path]:
  
    #Check whether cve_dir/cve_index folder has the folder for last vulnerable version, if not, we create one and regard it as dest path.
    two_versions=os.listdir(cve_dir+"/"+cve.cve_index)
    
    dest_path=(cve_dir+"/"+cve.cve_index+"/"+cve.last_vulnerable_version+"/",bin_name+".o")
    
    #print("src_path=",src_path)
    #print("dest_path=",dest_path)
    check_c_file(cve.vul_bins[path][bin_name],dest_path)
    
    #Check whether cve_dir/cve_index folder has the folder for last vulnerable version, if not, we create one and regard it as dest path.
    two_versions=os.listdir(cve_dir+"/"+cve.cve_index)
    
    dest_path=(cve_dir+"/"+cve.cve_index+"/"+cve.first_patched_version+"/",bin_name+".o")
 
    #print("src_path=",src_path)
    #print("dest_path=",dest_path)
    check_c_file(cve.vul_bins[path][bin_name],dest_path)

#Check whether destination .o file contains all functions in funcs
def check_c_file(funcs,dest_path):
  f_names=[]
  bin_path=""
  binaries=os.listdir(dest_path[0])
  for binary in binaries:
   if dest_path[1] in binary:
    bin_path=dest_path[0]+"/"+binary
    break
  output = subprocess.Popen( ["nm","-C","--defined-only",bin_path], stdout=subprocess.PIPE ).communicate()[0].decode("utf-8") 
  #print(type(output))
  #print(output)
  lines=output.split("\n")
  for line in lines:
   if " t " in line:
    f_names.append(line.split(" t ")[-1])
   elif " T " in line:
    f_names.append(line.split(" T ")[-1])
  for func in funcs:
   found=False
   for f_name in f_names: 
    #if func=="pop3_state_starttls_resp" and f_name=="pop3_state_starttls_resp.isra.13":
    # bp()
    if (func == f_name) or (func+".isra" in f_name) or (func+".constprop" in f_name):#SOmetimes compiler add .isra. as a suffix of a function name
     found=True
     break
  
    
   if "amissl.o" in dest_path[1] or "bearssl.o" in dest_path[1] or "gnutls.o" in dest_path[1] or "mbedtls.o" in dest_path[1] or "mesalink.o" in dest_path[1] or "nss.o" in dest_path[1] or "rustls.o" in dest_path[1] or "schannel.o" in dest_path[1] or "sectransp.o" in dest_path[1] or "wolfssl.o" in dest_path[1]  or "polarssl.o" in dest_path[1] or "darwinssl.o" in dest_path[1] or "cyassl.o" in dest_path[1] or "vtls.o" in dest_path[1] or "gtls.o" in dest_path[1] or "axtls.o" in dest_path[1] or "openldap.o" in dest_path[1]: # These ssl are hard to install thus we can not compile binary based on them.
      found=True
      break
   if found==False:
    print(func,"not in",dest_path)

   
   #else:
   # print(func,dest_path)
check_func_exist()

