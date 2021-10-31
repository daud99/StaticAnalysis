
import magic

file_type = magic.from_file ('/home/mabidm/malware-analysis/malwaresamples/1')
print('File Type From File: ',file_type)
#from buffer
file_type = magic.from_buffer(open('/home/mabidm/malware-analysis/malwaresamples/1','rb').read(2048) )
print('File Type From Buffer: ',file_type)
file_type = magic.from_buffer(open('/home/mabidm/malware-analysis/malwaresamples/1','rb').read(2048),mime=True )
print('File Type From Buffer With MIME: ',file_type)
