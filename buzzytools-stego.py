#/usr/bin/python3
import os
import binwalk
import sys
import stegoveritas
import re
import argparse
import codecs 
import shutil
import subprocess
import glob
import pytesseract

my_parser = argparse.ArgumentParser(description='Extract and analyze embeded files')

my_parser.add_argument('Path',
                       metavar='Path',
                       type=str,
                       help='Path to the file')

my_parser.add_argument('Flag_format',
                       metavar='Flag_format',
                       type=str,
                       help='Flag format (ex. actf)')

my_parser.add_argument('out_dir',
                       metavar='Output Directory',
                       type=str,
                       help='Output directory')

args = my_parser.parse_args()

filename = args.Path

out_dir = args.out_dir

flag_format = args.Flag_format



if not os.path.isfile(filename):
    print("File not found:" + sys.argv[1])
    exit()

if not flag_format:
    print("Flag format not specified")
    exit()



if not os.path.exists(out_dir):
    os.mkdir(out_dir)
shutil.copyfile(filename,out_dir+'/'+filename)
os.chdir(os.path.abspath(out_dir))


flag_format=flag_format+'{'

print("Looking for flag with format:"+flag_format+'}')


print("BINWALK=======================================")

for module in binwalk.scan(filename, signature=True, quiet=True, extract=True):
    for result in module.results:
        print ("\t%s    0x%.8X    %s" % (result.file.name, result.offset, result.description))
        if result.file.path in module.extractor.output:
            # These are files that binwalk carved out of the original firmware image, a la dd
            if result.offset in module.extractor.output[result.file.path].carved:
                print ("Carved data from offset 0x%X to %s" % (result.offset, module.extractor.output[result.file.path].carved[result.offset]))
            # These are files/directories created by extraction utilities (gunzip, tar, unsquashfs, etc)
            if result.offset in module.extractor.output[result.file.path].extracted:
                print ("Extracted %d files from offset 0x%X to '%s' using '%s'" % (len(module.extractor.output[result.file.path].extracted[result.offset].files),
                                                                                  result.offset,
                                                                                  module.extractor.output[result.file.path].extracted[result.offset].files[0],
                                                                                  module.extractor.output[result.file.path].extracted[result.offset].command))

print("stegoveritas=======================================")
os.system('stegoveritas '+filename)

print("Stegano output: resaults") 

print("printable=======================================")
content = open(filename,'rb')
stringsout = open('printable.txt','wb')
stringsout.write(codecs.decode(content.read(), 'ascii', errors='ignore').encode())
print('printable.txt')
print("strings=======================================")
os.system('strings -n7 '+str(filename)+' > strings.txt')
print('strings.txt')
print("OCR================================================")
ocr_out = open("ocr_out",'w')
for root, dirs, files in os.walk("."):
    for file in files:
        if file.endswith(".jpg"):
            tmp_out = pytesseract.image_to_string(os.path.join(root, file))
            print(tmp_out)
            ocr_out.writelines(tmp_out+'\n')
        if file.endswith(".jpeg"):
            tmp_out = pytesseract.image_to_string(os.path.join(root, file))
            print(tmp_out)
            ocr_out.writelines(tmp_out+'\n')
        if file.endswith(".png"):
            tmp_out = pytesseract.image_to_string(os.path.join(root, file))
            print(tmp_out)
            ocr_out.writelines(tmp_out+'\n')
        if file.endswith(".bmp"):
            tmp_out = pytesseract.image_to_string(os.path.join(root, file))
            print(tmp_out)
            ocr_out.writelines(tmp_out+'\n')

print('grep / possible flags =======================================')
gerp_out = subprocess.run(['grep -iR ' + str(flag_format)+' *'],shell=True,capture_output=True)
print(codecs.decode(gerp_out.stdout,errors='ignore'))
os.system("grep -iaR "+str(flag_format) + ' * > binarygrep.txt')
print("binary grep in binarygrep.txt")


#print(gerp_out.stdout.decode(erros='ignore'))
