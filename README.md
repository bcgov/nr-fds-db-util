# Overview

This repository currently contains the code to self sign an object that is 
located in object storage.  The intent of this code is so that many of the
images / reports / etc that are currently embedded in the database as
Large Objects (LOBS), can be migrated to object storage, saving significant
$.  The next step is to figure out how to integrate this code with some of 
the jasper reports, that glue the documents together into a coherent report.


# Contents

## ora-object-store

Code / docs related to migrating data from LOBS to object storage.
