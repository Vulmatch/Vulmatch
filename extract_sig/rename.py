import os

def rename_cve():
 cve_root='/home/nuc/Desktop/openjpeg_cve'
 cves=os.listdir(cve_root)
 for cve in cves:
   current_cve_path=cve_root+"/"+cve
   two_versions=os.listdir(current_cve_path)
   for version in two_versions:
     version_path=current_cve_path+"/"+version
     if not os.path.isdir(version_path):
       continue
     files=os.listdir(version_path)
     for each in files:
       if each.endswith(".c.o"):
         file_name=each.split(".c.o")[0]
         new_name=version_path+"/"+file_name+".o"
         old_name=version_path+"/"+each
         os.rename(old_name,new_name)
         print(old_name,"renamed to",new_name)


def rename_folder():
 root=input("please enter the folder:").strip("'")
 files=os.listdir(root)
 for each in files:
  if each.endswith(".c.o"):
   file_name=each.split(".c.o")[0]
   os.rename(root+"/"+each,root+"/"+file_name+".o")

rename_folder()
 
