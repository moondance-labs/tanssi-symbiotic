| Contract  | Address                                    | Parameters                                                                                                                                              |
| --------- | ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Vault     | 0xd88dDf98fE4d161a66FB836bee4Ca469eb0E4a75 | Collateral: wstETH<br>Curator: 0xe8616DEcea16b5216e805B0b8caf7784de7570E7<br>Epoch Duration: 7 days                                                     |
| Delegator | 0x85CF967A8DDFAf8C0DFB9c75d9E92a3C785A6532 | NetworkRestakeDelegator (allows restaking only across networks)                                                                                         |
| Slasher   | 0x57e5Fb61981fa1b43a074B2aeb47CCF157b19223 | Slasher (performs instant slashings)                                                                                                                    |
|           |                                            |                                                                                                                                                         |
| Vault     | 0xB118075733F3FF87184E96fb76dfa170326b47a5 | Collateral: rETH<br>Curator: 0x7358828e46001F447177E8c642270c178493E496<br>Epoch Duration: 7 days                                                       |
| Delegator | 0xC54610932b21Fb9897c623fBB336Ce7AdEC8F757 | FullRestakeDelegator (allows restaking across networks and across operators within a single network)                                                    |
| Slasher   | 0x853f90DFBCA2FCCD8C84f3bDc489Eb36b93841Ba | VetoSlasher (allows vetoing slashings)                                                                                                                  |
|           |                                            |                                                                                                                                                         |
| Vault     | 0xa4c81649c79f8378a4409178E758B839F1d57a54 | Collateral: wstETH<br>Curator: 0xe8616DEcea16b5216e805B0b8caf7784de7570E7<br>Epoch Duration: 7 days                                                     |
| Delegator | 0xADc06FD4F589Eb7E81356a2A3E7Cf68cb9917cBA | OperatorSpecificDelegator (allows an individual operator to enable restaking across networks) <br> Operator: 0xe8616DEcea16b5216e805B0b8caf7784de7570E7 |
| Slasher   | 0x64e81432517Df4DC63337b2874F358cdF3417697 | VetoSlasher (allows vetoing slashings) <br> Veto Duration: 1 day                                                                                        |