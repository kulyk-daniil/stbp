
# install fkae8 and radon packages
pip install flake8 radon mccabe


# check for errors (file)
python -m flake8 kulyk04/file.py

# check for errors (folder)
python -m flake8 kulyk04/


# compute mccabe metric (file)
python -m mccabe kulyk04/file.py

# compute mccabe metric (folder)
python -m mccabe kulyk04/*


# compute Cyclomatic Complexity metric (file)
python -m radon cc kulyk04/file.py

# compute Cyclomatic Complexity metric (folder)
python -m radon cc kulyk04/


# compute raw metrics (file)
python -m radon raw kulyk04/file.py

# compute raw metrics (folder)
python -m radon raw kulyk04/


# compute the Maintainability Index (file)
python -m radon mi kulyk04/file.py

# compute the Maintainability Index (folder)
python -m radon mi kulyk04/
