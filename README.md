# Lock Contract

## Release Note：

**1.0.0**

Script Hash: [0x7ebc95026b2cf0de2b0db59dac47822b80953f73]

Contract Address: ASHFXT9k2T28Sy8Zjj75HhUs4SFWV8VzKm

### Overview:

Lock refer to lock contract assets issued by Alchemint. 

### Descriptions:

Methods defined in account contract:

| Methods     | Parameters                         | Return value | Descriptions                                                 |
| ----------- | ---------------------------------- | ------------ | ------------------------------------------------------------ |
| openLock    | byte[] addr,string asset            | bool         | Create the lock account by addr.                            |
| getLockInfo | byte[] addr,string lockType         | byte[]       | Get the lock info by addr.                                  |
| reserve     | byte[] addr, string lockType, BigInteger lockMount| bool| Transfer asset to lock account.                        |
| withdraw    | byte[] addr, string lockType, BigInteger mount| bool| Transfer asset from lock account to itself by name.        |
| close       | byte[] addr, string lockType                  | bool      | Close the lock account.                              |
| setLockAdd  | byte[] addr, string addType, string lockAddr   | bool      | set lock add by addr.                                |
| getLockAdd  | byte[] addr, string addType                    | bool|  get lock addr by addr.                                    |
| setAccount  | string key, byte[] address |bool|setAccount method that set some account by admin,such as:sds_account\admin_account.|
| getAccount  | string key                       | byte[]          | getAccount by the key.                                      |
| setLockType | string key, BigInteger auth      | bool            | set lock type.                                              |
| getLockType | string key, BigInteger value     | string          | get lock type.                                              |
| setLockTime | string key                       | bool            | set lock time.                                              |
| getLockTime | string key                       | int             | get lock time.                                              |
| getLockGlobal| string key                      | int             | get lock global.                                       |

Notification defined in Contract:

| Notification | Parameters                        | Descriptions                                                 |
| ------------ | --------------------------------- | ------------------------------------------------------------ |
| lockOperator  | byte[] from, byte[] type, BigInteger optype, BigInteger value | Notification contains the four elements of lockOperator: addr(from), type ,operator type ,operator value.|
| lockAddrOperator| byte[] from, byte[] type, byte[] lockaddr| Notification contains the three elements of lockAddrOperator.|
