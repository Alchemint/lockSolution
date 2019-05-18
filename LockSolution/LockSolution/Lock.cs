using Neo.SmartContract.Framework;
using Neo.SmartContract.Framework.Services.Neo;
using Neo.SmartContract.Framework.Services.System;
using Helper = Neo.SmartContract.Framework.Helper;
using System.ComponentModel;
using System.Numerics;
using System;

namespace LOCK
{
    public class Lock : SmartContract
    {
        /** Operation of Lock records
        * addr,lockType,type,operated*/
        [DisplayName("lockOperator")]
        public static event deleLockOperated Locked;
        public delegate void deleLockOperated(byte[] from, byte[] type, BigInteger optype, BigInteger value);

        /** Operation of Lock records
        * addr,lockType,lockAddr*/
        [DisplayName("lockAddrOperator")]
        public static event deleLockAddrOperated LockedAddr;
        public delegate void deleLockAddrOperated(byte[] from, byte[] type, byte[] lockaddr);

        public delegate object NEP5Contract(string method, object[] args);

        //Default multiple signature committee account
        private static readonly byte[] committee = Helper.ToScriptHash("AZ77FiX7i9mRUPF2RyuJD2L8kS6UDnQ9Y7");

        //risk management
        private const string LOCK_TYPE_01 = "lock_01";
        private const string LOCK_TYPE_02 = "lock_02";
        private const string LOCK_TYPE_03 = "lock_03";
        private const string LOCK_TYPE_04 = "lock_04";

        //system account
        private const string SDS_ACCOUNT = "sds_account";
        private const string ADMIN_ACCOUNT = "admin_account";
        private const string LOCK_GLOBAL = "lockGlobal";

        //StorageMap lockInfo, key: addr+type
        //StorageMap account, key: key
        //StorageMap time, key: key
        //StorageMap global, key: str
        //StorageMap addrConfig,key:addr+type
        //StorageMap lockType,key:str

        //Transaction type
        public enum ConfigTranType
        {
            TRANSACTION_TYPE_OPEN = 1,
            TRANSACTION_TYPE_LOCK,
            TRANSACTION_TYPE_WITHDRAW,
            TRANSACTION_TYPE_SHUT
        }

        public static object Main(string method, object[] args)
        {
            if (Runtime.Trigger == TriggerType.Verification)
            {
                return false;
            }
            else if (Runtime.Trigger == TriggerType.Application)
            {
                var callscript = ExecutionEngine.CallingScriptHash;

                if (method == "openLock") return OpenLock((byte[])args[0], (string)args[1]);

                if (method == "getLockInfo") return GetLockInfo((byte[])args[0], (string)args[1]);

                if (method == "reserve") return Reserve((byte[])args[0], (string)args[1], (BigInteger)args[2]);

                if (method == "withdraw") return Withdraw((byte[])args[0], (string)args[1], (BigInteger)args[2]);

                if (method == "close") return Close((byte[])args[0], (string)args[1]);

                if (method == "setLockAdd") return SetLockAdd((byte[])args[0], (string)args[1], (string)args[2]);

                if (method == "getLockAdd") return GetLockAdd((byte[])args[0], (string)args[1]);
                //set account
                if (method == "setAccount") return SetAccount((string)args[0], (byte[])args[1]);

                if (method == "getAccount") return GetAccount((string)args[0]);

                if (method == "setLockType") return SetLockType((string)args[0], (BigInteger)args[1]);

                if (method == "getLockType") return GetLockType((string)args[0]);

                //set locktime
                if (method == "setLockTime") return SetLockTime((string)args[0], (BigInteger)args[1]);

                if (method == "getLockTime") return GetLockTime((string)args[0]);

                //get lock info
                if (method == "getLockGlobal") return GetLockGlobal();

            }
            return false;
        }

        [DisplayName("openLock")]
        public static bool OpenLock(byte[] addr, string asset)
        {
            if (!Runtime.CheckWitness(addr)) return false;

            StorageMap lockInfo = Storage.CurrentContext.CreateMap(nameof(lockInfo));
            byte[] lockCurr01 = lockInfo.Get(concatKey(addr, LOCK_TYPE_01));
            byte[] lockCurr02 = lockInfo.Get(concatKey(addr, LOCK_TYPE_02));
            byte[] lockCurr03 = lockInfo.Get(concatKey(addr, LOCK_TYPE_03));
            byte[] lockCurr04 = lockInfo.Get(concatKey(addr, LOCK_TYPE_04));

            var txid = ((Transaction)ExecutionEngine.ScriptContainer).Hash;
            if (lockCurr01.Length <= 0)
            {
                LockInfo info01 = new LockInfo();
                info01.locked = 0;
                info01.lockType = LOCK_TYPE_01;
                info01.owner = addr;
                info01.txid = txid;
                info01.asset = asset;
                info01.lockTime = 0;
                lockInfo.Put(concatKey(addr, LOCK_TYPE_01), Helper.Serialize(info01));
                //notify
                Locked(addr, LOCK_TYPE_01.AsByteArray(), (int)ConfigTranType.TRANSACTION_TYPE_OPEN, 0);
            }
            if (lockCurr02.Length <= 0)
            {
                LockInfo info02 = new LockInfo();
                info02.locked = 0;
                info02.lockType = LOCK_TYPE_02;
                info02.owner = addr;
                info02.txid = txid;
                info02.asset = asset;
                info02.lockTime = 0;
                lockInfo.Put(concatKey(addr, LOCK_TYPE_02), Helper.Serialize(info02));
                Locked(addr, LOCK_TYPE_02.AsByteArray(), (int)ConfigTranType.TRANSACTION_TYPE_OPEN, 0);

            }
            if (lockCurr03.Length <= 0)
            {
                LockInfo info03 = new LockInfo();
                info03.locked = 0;
                info03.lockType = LOCK_TYPE_03;
                info03.owner = addr;
                info03.txid = txid;
                info03.asset = asset;
                info03.lockTime = 0;
                lockInfo.Put(concatKey(addr, LOCK_TYPE_03), Helper.Serialize(info03));
                Locked(addr, LOCK_TYPE_03.AsByteArray(), (int)ConfigTranType.TRANSACTION_TYPE_OPEN, 0);
            }
            if (lockCurr04.Length <= 0)
            {
                LockInfo info04 = new LockInfo();
                info04.locked = 0;
                info04.lockType = LOCK_TYPE_04;
                info04.owner = addr;
                info04.txid = txid;
                info04.asset = asset;
                info04.lockTime = 0;
                lockInfo.Put(concatKey(addr, LOCK_TYPE_04), Helper.Serialize(info04));
                Locked(addr, LOCK_TYPE_04.AsByteArray(), (int)ConfigTranType.TRANSACTION_TYPE_OPEN, 0);
            }
            return true;
        }

        [DisplayName("getLockInfo")]
        public static LockInfo GetLockInfo(byte[] addr, string lockType)
        {
            if (addr.Length != 20)
                throw new InvalidOperationException("The parameter addr SHOULD be 20-byte.");

            if (lockType.Length <= 0)
                throw new InvalidOperationException("The parameter lockType SHOULD be longer than 0.");

            StorageMap lockInfo = Storage.CurrentContext.CreateMap(nameof(lockInfo));
            var result = lockInfo.Get(concatKey(addr, lockType)); //0.1
            if (result.Length == 0) return null;
            return Helper.Deserialize(result) as LockInfo;
        }

        [DisplayName("reserve")]
        public static Boolean Reserve(byte[] addr, string lockType, BigInteger lockMount)
        {
            if (!Runtime.CheckWitness(addr)) return false;

            if (addr.Length != 20)
                throw new InvalidOperationException("The parameter addr SHOULD be 20-byte addresses.");

            if (lockType.Length <= 0)
                throw new InvalidOperationException("The parameter lockType SHOULD be longer than 0.");

            if (lockMount <= 0)
                throw new InvalidOperationException("The parameter lockMount MUST be greater than 0.");

            StorageMap lockInfo = Storage.CurrentContext.CreateMap(nameof(lockInfo));
            var result = lockInfo.Get(concatKey(addr, lockType));

            if (result.Length == 0)
                throw new InvalidOperationException("The lockInfo can not be null.");

            LockInfo info = Helper.Deserialize(result) as LockInfo;

            string assetType = info.asset;
            BigInteger currentLock = info.locked;
            if (currentLock > 0)
                throw new InvalidOperationException("The lock has completed.");

            StorageMap account = Storage.CurrentContext.CreateMap(nameof(account));
            byte[] nep5AssetID = account.Get(assetType);
            //current contract
            byte[] to = ExecutionEngine.ExecutingScriptHash;
            if (to.Length == 0)
                throw new InvalidOperationException("The parameter to SHOULD be greater than 0.");

            object[] arg = new object[3];
            arg[0] = addr;
            arg[1] = to;
            arg[2] = lockMount;

            var AssetContract = (NEP5Contract)nep5AssetID.ToDelegate();

            if (!(bool)AssetContract("transfer", arg))
                throw new InvalidOperationException("The operation is exception.");

            //锁仓高度，锁仓时间，锁仓额度
            var lockHeight = Blockchain.GetHeight();
            var nowtime = Blockchain.GetHeader(lockHeight).Timestamp;
            info.locked = lockMount;
            info.lockHeight = lockHeight;
            info.lockTime = nowtime;

            //更新信息
            lockInfo.Put(concatKey(addr, lockType), Helper.Serialize(info));

            StorageMap global = Storage.CurrentContext.CreateMap(nameof(global));
            BigInteger currentTotal = global.Get(LOCK_GLOBAL).AsBigInteger();
            global.Put(LOCK_GLOBAL, currentTotal + lockMount);

            //notify
            Locked(addr, lockType.AsByteArray(), (int)ConfigTranType.TRANSACTION_TYPE_LOCK, lockMount);
            return true;
        }

        [DisplayName("withdraw")]
        public static Boolean Withdraw(byte[] addr, string lockType, BigInteger mount)
        {
            if (!Runtime.CheckWitness(addr)) return false;

            if (addr.Length != 20)
                throw new InvalidOperationException("The parameter addr SHOULD be 20-byte addresses.");

            if (lockType.Length <= 0)
                throw new InvalidOperationException("The parameter lockType SHOULD be longer than 0.");

            if (mount <= 0)
                throw new InvalidOperationException("The parameter mount MUST be greater than 0.");

            StorageMap lockInfo = Storage.CurrentContext.CreateMap(nameof(lockInfo));
            var result = lockInfo.Get(concatKey(addr, lockType));

            if (result.Length == 0)
                throw new InvalidOperationException("The lockInfo can not be null.");

            LockInfo info = Helper.Deserialize(result) as LockInfo;

            string assetType = info.asset;
            BigInteger currentLock = info.locked;
            uint lockTime = info.lockTime;
            if (currentLock <= 0)
                throw new InvalidOperationException("The lockMount can be greater than 0.");

            //Verify asset security
            if (mount > currentLock)
                throw new InvalidOperationException("The param is exception.");

            //Verify unLock time
            uint nowtime = Blockchain.GetHeader(Blockchain.GetHeight()).Timestamp;
            StorageMap time = Storage.CurrentContext.CreateMap(nameof(time));
            BigInteger timeInterval = time.Get(lockType).AsBigInteger();
            if ((nowtime - lockTime) < timeInterval)
                throw new InvalidOperationException("The unlock time has not come yet.");

            StorageMap account = Storage.CurrentContext.CreateMap(nameof(account));
            byte[] nep5AssetID = account.Get(assetType);

            byte[] from = ExecutionEngine.ExecutingScriptHash;
            if (from.Length == 0)
                throw new InvalidOperationException("The param is exception.");
            {
                object[] arg = new object[3];
                arg[0] = from;
                arg[1] = addr;
                arg[2] = mount;
                var nep5Contract = (NEP5Contract)nep5AssetID.ToDelegate();

                if (!(bool)nep5Contract("transfer_contract", arg)) throw new InvalidOperationException("The operation is error.");
            }
            info.locked = currentLock - mount;

            //更新信息
            lockInfo.Put(concatKey(addr, lockType), Helper.Serialize(info));

            StorageMap global = Storage.CurrentContext.CreateMap(nameof(global));
            BigInteger currentTotal = global.Get(LOCK_GLOBAL).AsBigInteger();
            if (currentTotal - mount >= 0)
            {
                global.Put(LOCK_GLOBAL, currentTotal - mount);
            }
            //notify
            Locked(addr, lockType.AsByteArray(), (int)ConfigTranType.TRANSACTION_TYPE_WITHDRAW, mount);
            return true;
        }

        [DisplayName("close")]
        public static Boolean Close(byte[] addr, string lockType)
        {
            if (!Runtime.CheckWitness(addr)) return false;

            if (addr.Length != 20)
                throw new InvalidOperationException("The parameter addr SHOULD be 20-byte addresses.");

            if (lockType.Length <= 0)
                throw new InvalidOperationException("The parameter lockType SHOULD be longer than 0.");

            StorageMap lockInfo = Storage.CurrentContext.CreateMap(nameof(lockInfo));
            var result = lockInfo.Get(concatKey(addr, lockType));

            if (result.Length == 0)
                throw new InvalidOperationException("The lockInfo can not be null.");

            LockInfo info = Helper.Deserialize(result) as LockInfo;

            BigInteger currentLock = info.locked;
            if (currentLock > 0)
                throw new InvalidOperationException("The lockMount is not 0.");

            lockInfo.Delete(concatKey(addr, lockType));

            //notify
            Locked(addr, lockType.AsByteArray(), (int)ConfigTranType.TRANSACTION_TYPE_SHUT, 0);
            return true;
        }

        [DisplayName("setAccount")]
        public static bool SetAccount(string key, byte[] address)
        {
            if (key.Length <= 0)
                throw new InvalidOperationException("The parameter key SHOULD be longer than 0.");

            if (address.Length != 20)
                throw new InvalidOperationException("The parameters address and to SHOULD be 20-byte addresses.");

            if (!checkAdmin()) return false;

            StorageMap account = Storage.CurrentContext.CreateMap(nameof(account));
            account.Put(key, address);
            return true;
        }

        [DisplayName("setLockType")]
        public static bool SetLockType(string key, BigInteger auth)
        {
            if (key.Length <= 0)
                throw new InvalidOperationException("The parameter key SHOULD be longer than 0.");

            if (!checkAdmin()) return false;
            StorageMap lockType = Storage.CurrentContext.CreateMap(nameof(lockType));
            if (auth > 0)
            {
                lockType.Put(key, auth);
            }
            else
            {
                lockType.Delete(key);
            }
            return true;
        }

        [DisplayName("getLockType")]
        public static BigInteger GetLockType(string key)
        {
            if (key.Length <= 0)
                throw new InvalidOperationException("The parameter key SHOULD be longer than 0.");

            StorageMap lockType = Storage.CurrentContext.CreateMap(nameof(lockType));
            return lockType.Get(key).AsBigInteger();
        }


        private static bool checkAdmin()
        {
            StorageMap account = Storage.CurrentContext.CreateMap(nameof(account));
            byte[] currAdmin = account.Get(ADMIN_ACCOUNT);

            if (currAdmin.Length > 0)
            {

                if (!Runtime.CheckWitness(currAdmin)) return false;
            }
            else
            {
                if (!Runtime.CheckWitness(committee)) return false;
            }
            return true;
        }

        [DisplayName("setLockAdd")]
        public static bool SetLockAdd(byte[] addr, string addType, string lockAddr)
        {
            if (addType.Length <= 0)
                throw new InvalidOperationException("The parameter addType SHOULD be longer than 0.");

            if (lockAddr.Length <= 0)
                throw new InvalidOperationException("The parameter lockAddr SHOULD be longer than 0.");

            if (addr.Length != 20)
                throw new InvalidOperationException("The parameters address and to SHOULD be 20-byte addresses.");

            if (!Runtime.CheckWitness(addr)) return false;

            //资产类型是否注册
            StorageMap lockType = Storage.CurrentContext.CreateMap(nameof(lockType));
            BigInteger auth = lockType.Get(addType).AsBigInteger();
            if (auth <= 0)
                throw new InvalidOperationException("The parameters addType is not auth.");

            StorageMap addrConfig = Storage.CurrentContext.CreateMap(nameof(addrConfig));
            addrConfig.Put(concatKey(addr, addType), lockAddr);

            LockedAddr(addr, addType.AsByteArray(), lockAddr.AsByteArray());
            return true;
        }

        [DisplayName("getLockAdd")]
        public static string GetLockAdd(byte[] addr, string addType)
        {
            if (addType.Length <= 0)
                throw new InvalidOperationException("The parameter addType SHOULD be longer than 0.");

            if (addr.Length != 20)
                throw new InvalidOperationException("The parameters address and to SHOULD be 20-byte addresses.");

            StorageMap addrConfig = Storage.CurrentContext.CreateMap(nameof(addrConfig));
            return addrConfig.Get(concatKey(addr, addType)).AsString();
        }


        [DisplayName("setLockTime")]
        public static bool SetLockTime(string type, BigInteger timeLimit)
        {
            if (type.Length <= 0)
                throw new InvalidOperationException("The parameter type SHOULD be longer than 0.");

            if (timeLimit <= 0)
                throw new InvalidOperationException("The parameters timeLimit SHOULD be larger than 0.");

            if (!checkAdmin()) return false;
            StorageMap time = Storage.CurrentContext.CreateMap(nameof(time));
            time.Put(type, timeLimit);
            return true;
        }

        [DisplayName("getLockGlobal")]
        public static BigInteger GetLockGlobal()
        {
            StorageMap global = Storage.CurrentContext.CreateMap(nameof(global));
            return global.Get(LOCK_GLOBAL).AsBigInteger();
        }

        [DisplayName("getLockTime")]
        public static BigInteger GetLockTime(string type)
        {
            StorageMap time = Storage.CurrentContext.CreateMap(nameof(time));
            return time.Get(type).AsBigInteger();
        }

        [DisplayName("getAccount")]
        public static byte[] GetAccount(string key)
        {
            StorageMap account = Storage.CurrentContext.CreateMap(nameof(account));
            return account.Get(key);
        }

        private static byte[] concatKey(byte[] addr, string type)
        {
            return addr.Concat(type.AsByteArray());
        }

        public class LockInfo
        {

            //creator
            public byte[] owner;

            //key of this lock
            public byte[] txid;

            //amount of locked collateral
            public BigInteger locked;

            //type of collateral 
            public string lockType;

            //lockTime 
            public uint lockTime;

            //lockHeight 
            public uint lockHeight;

            //assetType
            public string asset;

        }
    }
}