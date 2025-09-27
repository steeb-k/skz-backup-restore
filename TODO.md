# SKZ Backup and Restore — To‑Do List

Last updated: 2025-09-26

Legend: [P0] critical, [P1] important, [P2] nice-to-have

## Initial Implementation
- [ ] [P0] GUI wrapper for ImagingUtility
  - Create an application that looks like a "Modern" Windows UI application
  - Interface with main menu options on the left-hand side (styled like the "Settings" app in Windows 11) and functions in an interface on the right
  - Dark mode support needs to be integral throughout the entire design
  - This needs to be self-contained so that it can be portable and run in a Windows PE environment
  - Needs to be 100% compatible with x64 and ARM64 devices

## Backup Section
- [ ] [P0] VSS or SbS
  - All backup methods should include an option for "Sector-by-Sector" cloning if VSS can't work or errors are detected that keep VSS from working - it should be able to switch to sector-by-sector automatically if a failure is detected, but alert the end-user to it. 
- [ ] [P0] Full disk backup
  - This will be the primary use-case for now. We'll need to thoroughly test full-disk backups (including full-disk backups of the currently-booted disk.)
- [ ] [P0] Single partition backup
- [ ] [P1] Disk-to-disk clone
  - This should be able to expand the size of NTFS partitions to fill an entire disk - we'll have to look into this.

## Restore Section
- [ ] [P0] Restore disks option
  - Should have options that match the disk-to-disk clone feature, allowing NTFS partitions to be resized to fill entire disk (or shrink to fit a smaller disk, when possible)
- [ ] [P0] Restore partition option
  - Should have the ability to overwrite a partition on another disk
- [ ] [P0] Restore files option
  - Using ntfs-extract, should have a user-selectable checkbox interface to select individual files and folders for extraction
- [ ] [P1] MBR to GPT conversions
  - All restore options should have the ability to convert an MBR installation of Windows to GPT using built-in Windows commands to rebuild EFI partitions and BCD.

## Image Management Section
- [ ] [P0] Mount/browse images
  - Using ntfs-webdav, images should be able to be mounted to a drive letter to be browsed
- [ ] [P0] Verify images
  - Should have options to verify existing images using either normal or quick methods

## Utilities Section
- [ ] [P1] Convert MBR disks to GPT
  - Including recreating EFI partition and BCD
- [ ] [P1] Rebuild BCD for both MBR and GPT disks
- [ ] [P2] Recover registry hives from VSS copies
