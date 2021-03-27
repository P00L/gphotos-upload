import os
import csv

albums = []
with open('upload.csv', mode='w', newline='') as upload_file:
    employee_writer = csv.writer(upload_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

    # r=root, d=directories, f = files
    for r, d, f in os.walk('D:\\foto'):
        # print(f'{r}-{d}-{f}')
        for file in f:
            if file.endswith(".jpg") or file.endswith(".JPG"):
                album = r.split('\\')[-1]
                albums.append(album)
                file_name = os.path.join(r, file)
                description = ' '.join(r.split('\\')[2:])
                employee_writer.writerow([album, file_name, description])

print('\n'.join(sorted(set(albums))))
print(len(set(albums)))
