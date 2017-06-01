# rce-ml

A set of scripts I used in my research of x86-64 Linux binary analysis.

## Generating the dataset

```
python elf-find.py >> files.csv
```
This generate a CSV with all the SO files you have on your computer.

```
python gen-dataset.py files.csv data.sqlite
```

Extracts functions from the SO files in the CSV and puts them into SQLite database.

### Database structure:
```
CREATE TABLE IF NOT EXISTS files (
    sha256 TEXT UNIQUE,
    path TEXT,
    size INT,
    bitness INT
);

CREATE TABLE IF NOT EXISTS functions (
    sha256 TEXT UNIQUE,
    file_id INTEGER,
    virtual_address INTEGER,
    name TEXT,
    size INTEGER,
    bytes BLOB
)"""
```

Rest of the scripts just sample functions from the database, process the sample and output the result (Configuarble parameters are usually on top of the scripts and written in all caps):

* compare-ngrams.py <sqlite> <file1 id> <file2 id> - extracts n-grams from files and plots 30 most popular ones. The ngrams are noise-filtered.
* feature-extraction.py <sqlite> - extracts some features, applies PCA and plots the functions in 2D
* plot-distr <sqlite> - same as above but with byte frequency distribution as opposed to feature vector
* explore-graphs.py <sqlite> - lools at frequencies of functions' CFGs, writes shapes into OUT_DIR and prints the count for each graph shape.



