
Note: **LOCKLEVEL cannot currently be built using the instructions below**. Individual components that have Visual Studio projects, or are Python/PowerShell scripts, can still be built and run. These instructions and the build script will be updated at a later date.

How to build LOCKLEVEL:

1. Install cmake 3.3.1
1. Install the latest Python 2.7.x release
1. Install .Net 3.5 SP1 
1. Install Visual Studio 2013 or Visual Studio 2015 (**preferred**)
1. **Open a Visual Studio command prompt (MSBuild Command Prompt for VS2015 or Developer Command Prompt for VS2015)**. If you don't do this then you will get a build error of **ERROR Unable to find msbuild.exe in current working directory or system path**
1. If you have changed any of the penalty definitions, then you need to regenerate the remediations.js file used by the presentation layer
  1. Change to the tools directory: **cd locklevel\tools**
  1. Generate the remediations file: **python.exe penrem_check.py -i "..\." -o "."** 
  1. Move the remediations file to the presentation javascript folder: **move /y remediations.js "..\presentation\media\js\remediations.js"**
  1. Change back to the root LOCKLEVEL folder: **cd ..**
1. Change directory to the root LOCKLEVEL folder where llbuild.py is located: **cd locklevel**
1. Run the Python build script: **python.exe llbuild.py** 

The final build will be located at LOCKLEVEL\\_build\yyyyMMddHHmmss\LOCKLEVEL\ and there will also be a zip file containing that folder named LOCKLEVEL_yyyyMMddHHmmss.zip

A full build log will be located at LOCKLEVEL\\_build\build_log.txt

By default a Release build is created. To change it to Debug, run **python.exe llbuild.py -r Debug**

By default the build script tells cmake to generate and build Visual Studio 2015 projects for all unmanaged code. To change it to target Visual Studio 2013 projects, run **python.exe llbuild.py -v VS2013**


Windows 8/8.1/10 come with .Net 3.5 SP1, but it is not installed by default. If you are not connected to the Internet, then you will need to perform an offline installation of .Net 3.5:

1. Mount the Windows 8 or 8.1 ISO. Note which drive letter was used to mount the ISO (probably D:)
1. Open an administrator command prompt and run **dism.exe /online /enable-feature /FeatureName:NetFX3 /Source:drive letter:\sources\sxs /LimitAccess** 
  * e.g. if the ISO was mounted to the D: drive, run **dism.exe /online /enable-feature /FeatureName:NetFX3 /Source:D:\sources\sxs /LimitAccess**

If you are connected to the Internet, then you can open **Control Panel** > **Programs** > **Programs and Features** > **Turn Windows features on or off**. Then select the **.Net Framework 3.5 (includes .Net 2.0 and 3.0)** entry and click **OK**.