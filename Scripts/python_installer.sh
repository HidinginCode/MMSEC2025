#!/bin/bash

PYTHON_VERSION=3.10.13
PYTHON_SRC_DIR=Python-$PYTHON_VERSION
TAR_FILE=Python-$PYTHON_VERSION.tgz
INSTALL_PREFIX=/usr/local
LINK_PATH=/usr/local/bin/python

echo "Updating package list..."
sudo apt update

echo "Installing build dependencies..."
sudo apt install -y \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libncurses5-dev \
    libncursesw5-dev \
    libreadline-dev \
    libsqlite3-dev \
    libgdbm-dev \
    libdb5.3-dev \
    libbz2-dev \
    libexpat1-dev \
    liblzma-dev \
    tk-dev \
    wget \
    curl \
    llvm \
    libffi-dev \
    git

echo "Downloading Python $PYTHON_VERSION source..."
wget https://www.python.org/ftp/python/$PYTHON_VERSION/$TAR_FILE

echo "Extracting source..."
tar -xf $TAR_FILE

cd $PYTHON_SRC_DIR

echo "Configuring build..."
./configure --enable-optimizations --prefix=$INSTALL_PREFIX

echo "Building Python (this may take a while)..."
make -j$(nproc)

echo "Installing Python $PYTHON_VERSION..."
sudo make altinstall

cd ..

echo "Cleaning up..."
rm -rf $PYTHON_SRC_DIR $TAR_FILE

echo "Creating symlink $LINK_PATH -> $INSTALL_PREFIX/bin/python3.10"
if [ -L "$LINK_PATH" ] || [ -f "$LINK_PATH" ]; then
    echo "Removing existing $LINK_PATH"
    sudo rm -f "$LINK_PATH"
fi

sudo ln -s $INSTALL_PREFIX/bin/python3.10 $LINK_PATH

echo "Python installation complete."
$LINK_PATH --version

echo "Installing pyshark package"
python -m pip install pyshark

echo "Done"

