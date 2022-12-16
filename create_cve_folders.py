import pandas as pd
import os
import sys
from pdb import set_trace as bp
sys.path.append('/home/nuc/Desktop/VIVA/')
from find_bin_files_by_version import find_reachable_last_vulnerable_version, find_reachable_first_patched_version

#Create folders for all cves. The folder is like:
#                                                CVE1__________last_vulnerable_version_____binary file 1
#                                                        |                              |__binary file 2
#                                                        |                              |...
#                                                        |
#                                                        |_____fist_patched_version________binary file 1
#                                                                                       |__binary file 2
#                                                                                       |_...
#                                                CVE2__________last_vulnerable_version_____binary file 1
#                                                        |                              |__binary file 2
#                                                        |                              |...
#                                                        |
#                                                        |_____fist_patched_version________binary file 1
#                                                                                       |__binary file 2
#                                                                                       |_...                                                
def create_cve_folders():                        
 #Read the csv recording all the cve
 #xml_path=input("Please enter the cve.xml path:").strip("'")
 #sheet_name=input("Please enter the sheet name:")
 xml_path='/home/nuc/Downloads/vulnerable_projects/firmware/the_detailed_information_of_vulnerabilities.xlsx'
 sheet_name="dcs-6517&7517"
 df=pd.read_excel(xml_path, sheet_name)
 cve_index=list(filter(None, df["CVE"]))
 #cve_index=[str(x) for x in cve_index if str(x) != 'nan']
 last_versions=list(filter(None, df["Last"]))
 #last_versions=[str(x) for x in last_versions if str(x) != 'nan']
 print("cve_index:",cve_index)
 print("last_versions:",last_versions)
 
 #Read the records recording all the versions index. Make sure the record is in an descending order.
 #all_versions_record=input("Please enter the path recording all versions:").strip("'")
 all_versions_record="/home/nuc/Desktop/VIVA/openssl-versions"
 f=open(all_versions_record,"r")
 descending_versions=list(filter(None,f.read().split("\n")))

 #all_compiled_versions_path=input("Please enter the path compiling all versions:").strip("'")
 all_compiled_versions_path='/home/nuc/Downloads/vulnerable_projects/firmware/arm_hisiv_openssls'
 #Now create folders
 #output_dir=input("PLease enter the output folder:").strip("'")
 output_dir="/home/nuc/Desktop/firmware_cve/dcs-6517&7517"
 '''for i in range(0,len(cve_index)):
  last_version=last_versions[i]
  patched_version=look_for_first_patched_version(records,last_version)
  last_vulnerable_version=find_reachable_last_vulnerable_version(
	last_versions[current_cve_begin_index],
	descending_versions,
	all_compiled_versions_path)

   first_patched_version=find_reachable_first_patched_version(
	last_versions[current_cve_begin_index],
	descending_versions,
	all_compiled_versions_path)'''
 current_cve_begin_index=0
 current_cve_end_index=1
 while current_cve_end_index<len(cve_index):
  #print("current_cve_end_index=",current_cve_end_index)
  if str(cve_index[current_cve_end_index])=='nan':
   current_cve_end_index+=1
   continue
  else:
   if str(last_versions[current_cve_begin_index])=="nan":#Null record
    current_cve_end_index+=1
    current_cve_begin_index+=1
    continue 
   last_vulnerable_version=find_reachable_last_vulnerable_version(
	last_versions[current_cve_begin_index],
	descending_versions,
	all_compiled_versions_path)

   first_patched_version=find_reachable_first_patched_version(
	last_versions[current_cve_begin_index],
	descending_versions,
	all_compiled_versions_path)
   if last_vulnerable_version==None or first_patched_version==None:
    bp()
   print("cve:",cve_index[current_cve_begin_index])
   print("last_vulnerable_version:",last_vulnerable_version)
   print("first_patched_version:",first_patched_version)
   cve_path=output_dir+"/"+cve_index[current_cve_begin_index]
   if os.path.isdir(cve_path):#already has the folder, skip
     current_cve_end_index+=1
     current_cve_begin_index=current_cve_end_index
     continue
   os.mkdir(cve_path)
   vulnerable_folder_path=cve_path+"/"+last_vulnerable_version
   os.mkdir(vulnerable_folder_path)
   patched_folder_path=cve_path+"/"+first_patched_version
   os.mkdir(patched_folder_path)
   current_cve_begin_index=current_cve_end_index
   current_cve_end_index+=1

#GIven a list of all versions which is sorted in descending order and the last vulnerable version, find the first patched version.
'''def look_for_first_patched_version(descending_all_versions,last_version):
 index=descending_all_versions.index(last_version)-1
 patched_version=descending_all_versions[index]
 return patched_version'''


create_cve_folders()
 
