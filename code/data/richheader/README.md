# Rich Header

## Description

This is a collection of the work performed investigating the PE32 Rich Header.

## Standalone
To execute the standalone version please execute the following:

```
python3 standalone.py <filename>
```

## Web Version
The web version can be run as a local tornado server or through the included dockerfile.

#### Output
```json
{
    "compids": [
        {
            "mcv": "<str>",
            "pid": "<str>",
            "cnt": "<str>",
        }
    ],
    "compids_dup": "<boolean>",
    "csum_calc": "<int>",
    "csum_file": "<int>",
    "csum_valid": "<boolean>",
    "error": "<int>",
    "offset": "<int>",
}
```

#### Docker Usage
Build and start the docker container using the following commands

```
docker build -t richheader .
sudo docker run --name rich_header -v /tmp:/tmp:ro -p 8080:8080 richheader
```

Place the files you wish to extract the Rich Header from in /tmp and access using 
`http://127.0.0.1:8080/analyze/?obj=<file_name>`

To read about the service please see
`http://127.0.0.1:8080/`

## Acknowledgement
This work was created with the blood sweat and tears of mamy people. 
Thank you
* Zachary Hanif
* Julian Kirsch
* Bojan Kolosnjaji
* Christian von Pentz
* Marcel Schumacher
* George Webster
* Huang Xiao
