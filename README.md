# 3mystic_hashicorp
A set of common files that are used for interacting with hashicorp

# Install

## pip

This project is currently designed to be installed via pip
pip install https://github.com/3MysticApes/3mystic_hashicorp

Once installed you will get the following command:
3mystic_hashicorp

The above command currently just lets you know the scripts have been installed and are usable for reference. It also will let you know what version of the toolset is installed.


# Contribute

This project is packaged using Hatch. If you need to install Hatch please refer to their documentation
https://hatch.pypa.io/latest/install/


You should be able to run the following command in the root directory for a general status
hatch status

Then from the root directory you can run
pip install ./

I would suggest while you are debugging issues to install it with the command below. Once you are done with your development you can uninstall. This allows you to make edits and test easier.
pip install -e ./
https://pip.pypa.io/en/stable/cli/pip_install/#cmdoption-e