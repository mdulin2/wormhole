#!/bin/bash 

# Check if GOPATH is set
if [ -z "$GOBIN" ]; then
    echo "GOBIN is not set"
    echo "You can set it by running: export GOBIN=\$HOME/go/bin or where your GOBIN is located."
    exit 1
else
    echo "GOBIN is set to: $GOPATH"
fi 

# Ensuring that GOBIN is in PATH
if [[ ":$PATH:" == *":$GOBIN:"* ]]; then
    echo "GOBIN is in PATH"
else
    echo "GOBIN is NOT in PATH"
    echo "You can add it by running: export PATH=\$PATH:\$GOBIN"
    exit 1
fi

echo "Checking Python and pip installation..."
# Check if Python is installed
if command -v python3 &> /dev/null; then
    python_cmd="python3"
else
    echo "Python is not installed. Please install Python 3.x"
    exit 1
fi

# Checking if pip installed
if command -v pip3 &> /dev/null; then
    pip_cmd="pip3"
else
    echo "Pip is not installed. Please install Pip3"
    exit 1
fi 

# Check if capslock is installed
if command -v capslock &> /dev/null; then
    echo "capslock is already installed"
else
    echo "capslock is not installed. Installing now..."

    # Installing capslock 
    go install github.com/google/capslock/cmd/capslock@v0.2.7

    # Check if installation was successful
    if command -v capslock &> /dev/null; then
        echo "capslock has been successfully installed"
    else
        echo "Failed to install capslock"
        exit 1
    fi
fi

# Define variables
VENV_NAME="capslock_venv"
REQUIREMENTS_FILE="requirements.txt"

# Check if virtualenv is installed
if ! command -v virtualenv &> /dev/null; then
    echo "virtualenv not found. Installing..."
    pip install virtualenv
fi

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_NAME" ]; then
    echo "Creating virtual environment: $VENV_NAME"
    virtualenv "$VENV_NAME"
else
    echo "Virtual environment already exists: $VENV_NAME"
fi

# Activate the virtual environment
echo "Activating virtual environment..."
source "$VENV_NAME/bin/activate"

# Check if requirements file exists
if [ -f "$REQUIREMENTS_FILE" ]; then
    echo "Installing requirements from $REQUIREMENTS_FILE..."
    pip install -r "$REQUIREMENTS_FILE"
    echo "Requirements installed successfully."
fi 

#SCRIPT_PATH=dirname "$(realpath $0)"
temp=$( realpath "$0"  )
SCRIPT_PATH=$(dirname "$temp")

# ## Capslock 
### Build node as is. Given that this is used to push code in a PR, this should work fine.
# TODO - should we remove this? Is it necessary?
# echo Building node to ensure that Capslock is able to.
# NODE_PATH=$(realpath $(git rev-parse --git-dir)/../)/
# cd $NODE_PATH
# make node

if [ $? -ne 0 ]; then
  echo "Building node failed"
  echo "Please fix to run with 'make node'". 
  exit 1
fi 

### Run capslock 
echo Running capslock
cd $NODE_PATH/node;
capslock -output=json > $NODE_PATH/node/.capabilities_tmp.json
if [ $? -ne 0 ]; then
  echo "Running capslock failed"
  exit 1
fi 

## Copy capslock file 
mv $NODE_PATH/node/.capabilities_tmp.json $SCRIPT_PATH/.capabilities_tmp.json

## Run diff script to edit proper location
cd $SCRIPT_PATH; 
python3 $SCRIPT_PATH/capslock_diff.py --standalone true --old $SCRIPT_PATH/.capabilities_tmp.json --output default
if [ $? -ne 0 ]; then
  echo "Running capslock_diff.py failed"
  exit 1
fi 

## Delete temporary files
rm $SCRIPT_PATH/.capabilities_tmp.json

rm -rf $VENV_NAME