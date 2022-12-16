from common_library import func_vul_patch_signature,p_c_sig,sub_p_c_sig
from pdb import set_trace as bp
import pickle
import os


def read_bin(pickle_file):
 f=open(pickle_file,'rb')
 sig_list=pickle.load(f)
 print("length of sig_list:",len(sig_list))
 sig_number=0
 for sig in sig_list:
  sig_number+=1
  print("")
  print(sig.function_name,sig_number) 
  print("vul signature:")
  if sig.vul_signature[0]=="many_changed":#If is changed site
    print("many_changed")
    for sub_sig in sig.vul_signature[1]:
     if type(sub_sig)==sub_p_c_sig:
      print("parent:",sub_sig.p)
      print("children:",sub_sig.c)
     else:
      print(sub_sig)
    print("vul unique insns:")
    print(sig.vul_signature[2])
  elif sig.vul_signature[0]=="one_changed":#If is changed site
   print("one_changed")
   print("parent:",sig.vul_signature[1].p)
   print("children:",sig.vul_signature[1].c)
   print("vul unique insns:")
   print(sig.vul_signature[2])
  elif sig.vul_signature[0]=="deleted":#If is delete site
   print("deleted")
   print(sig.vul_signature[1])
  elif sig.vul_signature[0]=="added":#If is added site
   print("added")
   for item in sig.vul_signature[1]:
    #if item==None:
    # bp()
    for p_c_struct in item:
     if len(p_c_struct.p)==0:
      print("Parent:",p_c_struct.p)
     elif type(p_c_struct.p)==dict:
      print("Parent:",p_c_struct.p)
      #for parent in p_c_struct.p:
      # print("Parent:",parent)
     else:
      print("Parent:",p_c_struct.p)

     if len(p_c_struct.c)==0:
      print("Child:",p_c_struct.c)
     elif type(p_c_struct.c)==dict:
      print("Child:",p_c_struct.c)
      #for child in p_c_struct.c:
      # print("Child:",child)
     else:
      print("Child:",p_c_struct.c)
  print("patch unique insns:")
  print(sig.patch_signature)
  

def read_src(pickle_file):
 f=open(pickle_file,'rb')
 sig_list=pickle.load(f)
 print("length of sig_list:",len(sig_list))
 sig_number=0
 for sig in sig_list:
  sig_number+=1
  print("")
  print(sig.function_name,sig_number)
  print("vul signature:",sig.vul_signature)
  print("patch signature:",sig.patch_signature)
 
def show_pickle():
  pickle_file=input("Please enter the pickle file:").strip("'")
  file_name=pickle_file.split("/")[-1]
  if file_name.startswith("bin_"):
   read_bin(pickle_file)
  else:
   read_src(pickle_file)

def show_bin_n_src_sig():
  pickle_file=input("Please enter the pickle file:").strip("'")
  cve_path=pickle_file[:pickle_file.rfind("/")]
  file_name=pickle_file[pickle_file.rfind("/")+1:]
  bin_pickle_file=""
  src_pickle_file=""
  if file_name.startswith("bin_"):
    src_pickle_file=cve_path+"/"+file_name[4:].replace("_insn_sig.pickle",".c_insn_sig.pickle")
    bin_pickle_file=pickle_file
  else:
    src_pickle_file=pickle_file
    bin_pickle_file=cve_path+"/bin_"+file_name.replace(".c_insn_sig.pickle","_insn_sig.pickle")
  
  src_pickle_f=open(src_pickle_file,'rb')
  src_sig_list=pickle.load(src_pickle_f)

  bin_pickle_f=open(bin_pickle_file,'rb')
  bin_sig_list=pickle.load(bin_pickle_f)
  
  for src_sig,bin_sig in zip(src_sig_list,bin_sig_list):
    print(src_sig.function_name)
    print("vul signature:",src_sig.vul_signature)
    for item in bin_sig.vul_signature:
     if type(item)==str:
      print(item)
     else:
      for p_c_struct in item:
       if type(p_c_struct.p[0])==list:
        for parent in p_c_struct.p:
         print("Parent:",parent)
       else:
         print("Parent:",p_c_struct.p)

       if type(p_c_struct.c[0])==list:
        for child in p_c_struct.c:
         print("Child:",child)
       else:
         print("Child:",p_c_struct.c)
   
    print("patch signature:",src_sig.patch_signature)
    print(bin_sig.patch_signature)
    print("")

def calculate_null_bin_pickle():
 null_bin_pickle=0
 all_bin_pickle=0
 cve_root=input("Please enter the cve folder:").strip("'")
 files=os.listdir(cve_root)
 for each in files:
  if os.path.isdir(cve_root+"/"+each):
   current_cve_path=cve_root+"/"+each
   each_cve_files=os.listdir(current_cve_path)
   for each_cve_each in each_cve_files:
    if each_cve_each.startswith("bin_") and each_cve_each.endswith(".pickle"):
     all_bin_pickle+=1
     bin_pickle_file=current_cve_path+"/"+each_cve_each
     f=open(bin_pickle_file,'rb')
     sig_list=pickle.load(f)
     if len(sig_list)==0:
      null_bin_pickle+=1
 print("bin pickle file total number:",all_bin_pickle)
 print("null bin pickle file number:",null_bin_pickle)
 print("valid bin pickle file number:",all_bin_pickle-null_bin_pickle)

def calculate_avg_sig_size():
 cve_root=input("Please enter the cve folder:").strip("'")
 files=os.listdir(cve_root)
 total_sig_size=0
 cve_num=0
 for each in files:
  if os.path.isdir(cve_root+"/"+each):
   current_cve_path=cve_root+"/"+each
   each_cve_files=os.listdir(current_cve_path)
   one_cve_sig_size=0
   cve_num+=1
   for each_cve_each in each_cve_files:
    if each_cve_each.startswith("bin_") and each_cve_each.endswith(".pickle"):
     bin_pickle_file=current_cve_path+"/"+each_cve_each
     f=open(bin_pickle_file,'rb')
     sig_list=pickle.load(f)
     if len(sig_list)!=0:
      size=one_sig_list_all_size(sig_list)
      one_cve_sig_size+=size
   total_sig_size+=one_cve_sig_size
 
 avg=total_sig_size*1.0/cve_num
 print("avg signature size",avg,"cve_num",cve_num)

def calculate_null_bin_vul_sig():
 cve_root=input("Please enter the cve folder:").strip("'")
 files=os.listdir(cve_root)
 all_sig=0
 null_vul_sig=0
 for each in files:
  if os.path.isdir(cve_root+"/"+each):
   current_cve_path=cve_root+"/"+each
   each_cve_files=os.listdir(current_cve_path)
   
   for each_cve_each in each_cve_files:
    if each_cve_each.startswith("bin_") and each_cve_each.endswith(".pickle"):
     bin_pickle_file=current_cve_path+"/"+each_cve_each
     f=open(bin_pickle_file,'rb')
     sig_list=pickle.load(f)
     if len(sig_list)!=0:
      for sig in sig_list:
       if sig.vul_signature=={}:
        print(bin_pickle_file)
        null_vul_sig+=1
       all_sig+=1
      
 print("Null vul sig",null_vul_sig,"all_sig",all_sig)


def calculate_null_src_vul_sig():
 cve_root=input("Please enter the cve folder:").strip("'")
 files=os.listdir(cve_root)
 all_sig=0
 null_vul_sig=0
 for each in files:
  if os.path.isdir(cve_root+"/"+each):
   current_cve_path=cve_root+"/"+each
   each_cve_files=os.listdir(current_cve_path)
   
   for each_cve_each in each_cve_files:
    if each_cve_each.endswith(".c_insn_sig.pickle"):
     src_pickle_file=current_cve_path+"/"+each_cve_each
     f=open(src_pickle_file,'rb')
     sig_list=pickle.load(f)
     if len(sig_list)!=0:
      for sig in sig_list:
       if sig.vul_signature=={}:
        #print(src_pickle_file)
        null_vul_sig+=1
       all_sig+=1
      
 print("Null vul sig",null_vul_sig,"all_sig",all_sig)

def one_sig_list_all_size(sig_list):
 total_size=0
 for sig in sig_list:
  one_sig_size=len(sig.vul_signature)+len(sig.patch_signature)
  total_size+=one_sig_size
 return total_size

def find_null_bin_parent_child_vul_sig():
 cve_root=input("Please enter the cve folder:").strip("'")
 files=os.listdir(cve_root)
 for each in files:
  if os.path.isdir(cve_root+"/"+each):
   current_cve_path=cve_root+"/"+each
   each_cve_files=os.listdir(current_cve_path)
   for each_cve_each in each_cve_files:
    if each_cve_each.startswith("bin_") and each_cve_each.endswith(".pickle"):
     bin_pickle_file=current_cve_path+"/"+each_cve_each
     f=open(bin_pickle_file,'rb')
     sig_list=pickle.load(f)
     for sig in sig_list:
      if type(sig.vul_signature)!=dict:
       for item in sig.vul_signature:
        for p_c_struct in item:
         if len(p_c_struct.p)==0 or len(p_c_struct.c)==0:
           print(bin_pickle_file)
       
 

#show_bin_n_src_sig()
show_pickle()
#calculate_null_bin_pickle()
#calculate_avg_sig_size()
#calculate_null_bin_vul_sig()
#calculate_null_src_vul_sig()
#find_null_bin_parent_child_vul_sig()
