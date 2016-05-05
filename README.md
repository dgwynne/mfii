The `mfii` driver provides support for the MegaRAID SAS Fusion family of
RAID controllers. This family of controllers includes the following chips:

- SAS2008
- SAS3008
- SAS3108

The MegaRAID SAS Fusion family does not include previous generations
of the MegaRAID SAS family. The programming interface in previous
generations of MegaRAID SAS controllers is significantly different to
the one used in the Fusion family, which complicates support for both
styles of controller in a single driver.
