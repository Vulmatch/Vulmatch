import os

def main():
 curl_root=input("Please enter the curl root folder:").strip("'")
 files=os.listdir(curl_root)
 for each in files:
  if os.path.isdir(curl_root+"/"+each):
   current_curl_path=curl_root+"/"+each
   mk_path=current_curl_path+"/"+"Makefile"
   if not os.path.exists(mk_path):
    print("Not exists",mk_path)
    continue
   f=open(mk_path,'r')
   content=f.read()
   lines=content.split("\n")
   for line in lines:
    if line.startswith("CFLAG"):
     print(each,line)
     print("")
     break


main()
