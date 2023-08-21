# LinkScope Client Module Packs

This repository holds module packs for LinkScope Client.
It is added as a source by default on new installations of LinkScope.

You can use this as a template to create your own public or private sources,
or contribute to it directly by adding or updating module packs.

The LinkScope Client will automatically check and sync all sources on startup.

## How module packs work

Each module pack consists of one YAML file and one or more plugin folders.
The YAML file is what defines the module pack. Each of the folders is
considered to be one distinct module.

The `Example Module` folder demonstrates the expected structure of a module.
It is part of the 'Example Module Pack' module pack, which is defined in
`examplepack.yml`.

### The Module Pack YAML file

Each module pack YAML file must contain the following:
- An `author` field, with a string stating the author of the module pack
- A `label` field, with a string stating the name of the module pack
- A `description` field, with a string explaining what functions the
modules in the module pack contain, and what the module pack helps the user
to do
- An `icon` field, containing a base64-encoded SVG image
- And a `modules` field, containing a list with the names of the folders
that make up the module pack.

### The Module folder

Each module folder contains the following:
- An `Assets` folder, optionally containing entity icons and/or banners
- An `Entities` folder, optionally containing XML files with entity definitions
- A `Resolutions` folder, optionally containing LinkScope resolutions
(i.e. Python files)
- A `module.yml` file with the following labels:
  - `author`
  - `description`
  - `version`
- A `requirements.txt` file that is used to install any python libraries
that the module's resolutions need.