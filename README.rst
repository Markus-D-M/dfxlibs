::

  > dfxlibs -h
    usage: dfxlibs [-h] -m META_FOLDER [--meta_create] [-i IMAGE [IMAGE ...]] [--part PART] [-pf] [-pvss]
                   [--hash HASH [HASH ...]] [--filetypes] [-pevtx] [-preg] [-pusn] [-ppf] [-cevtx] [-cusn] [-cpf]
                   [-lp] [-e EXTRACT [EXTRACT ...]]

    dfxlibs: A python digital forensics toolkit (version 0.0.2)

    optional arguments:
      -h, --help            show this help message and exit

    General Arguments:
      These parameters are used in all categories.

      -m META_FOLDER, --meta_folder META_FOLDER
                            folder to store and load meta information
      --meta_create         create meta information folder if not exists
      -i IMAGE [IMAGE ...], --image IMAGE [IMAGE ...]
                            forensic image file. This parameter is stored in the meta information folder, so it is
                            only needed for the first call on an image. If this parameter is given on proceeding
                            calls, it will overwrite the parameter in the meta information folder (so be careful to
                            not mix up different images in one meta information folder).
      --part PART           Specify partition for actions like --prepare_files. It must be named as given in the
                            --list_partitions output. Without --part all partitions in an image will be included.

    Preparation:
      These arguments prepare the data from the image for further analysis

      -pf, --prepare_files  Scan files and directories of all partitions. You can specify a partition with --part.
                            The file entries will be stored in the meta_folder in a sqlite database
      -pvss, --prepare_vss  Scan for files and directories in volume shadow copies of all partitions. You can
                            specify a partition with --part. The file entries will be stored in the meta_folder in a
                            sqlite database
      --hash HASH [HASH ...]
                            Hash all files <256 MiB of all partitions. You can specify a partition with --part.
                            Possible algorithms are md5, sha1, sha256 and tlsh. A minimum filesize of 50 bytes is
                            required for tlsh. The result is stored in the file database.
      --filetypes           turn on signature based detection of filetypes of all files in all partitions. The
                            result is stored in the file database. You can specify a partition with --part.
      -pevtx, --prepare_evtx
                            read all windows evtx logs in a given Image and stores them in a sqlite database in the
                            meta_folder. You can specify a partition with --part.
      -preg, --prepare_reg  read the windows registry and stores them in a sqlite database in the meta_folder. You
                            can specify a partition with --part.
      -pusn, --prepare_usn  reading ntfs usn journals and stores the entries in a sqlite database in the
                            meta_folder. You can specify a partition with --part.
      -ppf, --prepare_prefetch
                            reading prefetch files and stores the entries in a sqlite database in the meta_folder.
                            You can specify a partition with --part.

    Carving:
      These arguments are for different carving options.

      -cevtx, --carve_evtx  carve for windows evtx entries and stores them in the same database as for the
                            --prepare_evtx argument
      -cusn, --carve_usn    carve for ntfs usn journal entries and stores them in the same database as for the
                            --prepare_usn argument
      -cpf, --carve_prefetch
                            carve for prefetch files and stores them in the same database as for the
                            --prepare_prefetch argument

    Special actions:
      These parameters contains short and simple actions.

      -lp, --list_partitions
                            print partition list
      -e EXTRACT [EXTRACT ...], --extract EXTRACT [EXTRACT ...]
                            Extracts files from the image and stores them to the meta_folder. You have to give the
                            full path and filename (with leading slash - even slashes instead of backslashes for
                            windows images) or a meta address. As default source "filesystem" for regular files in
                            the image will be used. You can give another file-source (e.g. "vss#0" for shadow copy
                            store 0) by just adding it in front of your path and separate it with a colon (e.g.
                            "vss#0:/path/testfile.txt" for /path/testfile.txt from vss#0). You can give multiple
                            files at once

