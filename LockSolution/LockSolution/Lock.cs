using Neo.SmartContract.Framework;
using Neo.SmartContract.Framework.Services.Neo;
using Neo.SmartContract.Framework.Services.System;
using Helper = Neo.SmartContract.Framework.Helper;
using System;
using System.Numerics;
using System.ComponentModel;

namespace LockSolution
{
    public class Lock : SmartContract
    {
        /** Operation of Lock records
          * addr,lockType,type,operated*/
        [DisplayName("lockOperator")]
        public static event Action<byte[], byte[],BigInteger, BigInteger> Operated;

        public delegate object NEP5Contract(string method, object[] args);

        //Default multiple signature committee account
        private static readonly byte[] committee = Helper.ToScriptHash("AZ77FiX7i9mRUPF2RyuJD2L8kS6UDnQ9Y7");


        /** 
         * Static param
         */

        //risk management
        private const string LOCK_TYPE_01 = "lock_01";
        private const string LOCK_TYPE_02 = "lock_02";
        private const string LOCK_TYPE_03 = "lock_03";
        private const string LOCK_TYPE_04 = "lock_04";


        //system account
        private const string SDS_ACCOUNT = "sds_account";
        private const string ADMIN_ACCOUNT = "admin_account";
        private const string LOCK_GLOBAL = "lockGlobal";

        /*     
        * Key wrapper
        */
        private static byte[] getLockKey(byte[] addr,string type) => new byte[] { 0x12 }.Concat(type.AsByteArray()).Concat(addr);
        private static byte[] getAccountKey(byte[] account) => new byte[] { 0x15 }.Concat(account);
        private static byte[] getTimeKey(string type) => new byte[] { 0x18 }.Concat(type.AsByteArray());
        private static byte[] getLockGlobalKey(byte[] key) => new byte[] { 0x19 }.Concat(key);

        //Transaction type
        public enum ConfigTranType
        {
            TRANSACTION_TYPE_OPEN = 1,
            TRANSACTION_TYPE_LOCK,
            TRANSACTION_TYPE_WITHDRAW,
            TRANSACTION_TYPE_SHUT
        }


        /// <summary>
        ///   This smart contract is designed to implement NEP-5
        ///   Parameter List: 0710
        ///   Return List: 05
        /// </summary>
        /// <param name="operation">
        ///     The methos being invoked.
        /// </param>
        /// <param name="args">
        ///     Optional input parameters used by NEP5 methods.
        /// </param>
        /// <returns>
        ///     Return Object
        /// </returns>
        public static Object Main(string operation, params object[] args)
        {
            var magicstr = "2019-05-06 18:40:10";

            if (Runtime.Trigger == TriggerType.Verification)
            {
                return false;
            }
            else if (Runtime.Trigger == TriggerType.Application)
            {
                var callscript = ExecutionEngine.CallingScriptHash;

                if (operation == "openLock")
                {
                    if (args.Length != 3) return false;
                    byte[] addr = (byte[])args[0];
                    string ethAddr = (string)args[1];
                    string asset = (string)args[2];

                    if (!Runtime.CheckWitness(addr)) return false;
                    return openLock(addr, ethAddr,asset);
                }

                if (operation == "getLockInfo")
                {
                    if (args.Length != 2) return false;
                    byte[] addr = (byte[])args[0];
                    string lockType = (string)args[1];

                    byte[] lockInfo = getLockInfo(addr,lockType);
                    if (lockInfo.Length == 0)
                        return null;
                    return Helper.Deserialize(lockInfo) as LockInfo;
                }

                //locked nep5 asset to Lock account
                if (operation == "reserve")
                {
                    if (args.Length != 3) return false;
                    byte[] addr = (byte[])args[0];
                    string lockType = (string)args[1];
                    //NEP5 Asset mount 
                    BigInteger mount = (BigInteger)args[2];

                    if (!Runtime.CheckWitness(addr)) return false;
                    return reserve(addr,lockType,mount);
                }
                //get asset from Lock
                if (operation == "withdraw")
                {
                    if (args.Length != 3) return false;

                    byte[] addr = (byte[])args[0];
                    string lockType = (string)args[1];
                    //NEP5 asset
                    BigInteger mount = (BigInteger)args[2];

                    if (!Runtime.CheckWitness(addr)) return false;

                    return withdraw(addr,lockType,mount);
                }

                //close a lock
                if (operation == "close")
                {
                    if (args.Length != 2) return false;
                    byte[] addr = (byte[])args[0];
                    string lockType = (string)args[1];

                    if (!Runtime.CheckWitness(addr)) return false;
                    return close(addr,lockType);
                }
                if (operation == "getLockGlobal")
                {
                    return getLockGlobal();
                }
                if (operation == "setAccount")
                {
                    if (args.Length != 2) return false;

                    string key = (string)args[0];
                    byte[] address = (byte[])args[1];
                    //only committee account
                    if (!checkAdmin()) return false;
                    return setAccount(key, address);
                }
                if (operation == "getAccount")
                {
                    if (args.Length != 1) return false;

                    string key = (string)args[0];
                    return getAccount(key);
                }
                if (operation == "setLockTime")
                {
                    if (args.Length != 2) return false;

                    string key = (string)args[0];
                    BigInteger time = (BigInteger)args[1];
                    //only committee account
                    if (!checkAdmin()) return false;
                    return setLockTime(key,time);
                }
                if (operation == "getLockTime")
                {
                    if (args.Length != 1) return false;

                    string key = (string)args[0];
                    return getLockTime(key);
                }
            }
            return false;
        }


        private static BigInteger getLockGlobal()
        {
            byte[] lockKey = getLockGlobalKey(LOCK_GLOBAL.AsByteArray());
            BigInteger total = Storage.Get(Storage.CurrentContext, lockKey).AsBigInteger();
            return total;
        }

        private static bool checkAdmin()
        {
            byte[] currAdmin = Storage.Get(Storage.CurrentContext, getAccountKey(ADMIN_ACCOUNT.AsByteArray()));
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

        private static bool openLock(byte[] addr, string ethAddr,string asset)
        {
            byte[] key01 = getLockKey(addr,LOCK_TYPE_01);
            byte[] key02 = getLockKey(addr,LOCK_TYPE_02);
            byte[] key03 = getLockKey(addr,LOCK_TYPE_03);
            byte[] key04 = getLockKey(addr,LOCK_TYPE_04);

            byte[] lockCurr01 = Storage.Get(Storage.CurrentContext, key01);
            byte[] lockCurr02 = Storage.Get(Storage.CurrentContext, key02);
            byte[] lockCurr03 = Storage.Get(Storage.CurrentContext, key03);
            byte[] lockCurr04 = Storage.Get(Storage.CurrentContext, key04);

            var txid = ((Transaction)ExecutionEngine.ScriptContainer).Hash;
            if (lockCurr01.Length <= 0) {
                LockInfo info01 = new LockInfo();
                info01.lockAddr = ethAddr;
                info01.locked = 0;
                info01.lockType = LOCK_TYPE_01;
                info01.owner = addr;
                info01.txid = txid;
                info01.status = 1;
                info01.asset = asset;
                Storage.Put(Storage.CurrentContext, key01, Helper.Serialize(info01));
            }
            if (lockCurr02.Length <= 0)
            {
                LockInfo info02 = new LockInfo();
                info02.lockAddr = ethAddr;
                info02.locked = 0;
                info02.lockType = LOCK_TYPE_02;
                info02.owner = addr;
                info02.txid = txid;
                info02.status = 1;
                info02.asset = asset;
                Storage.Put(Storage.CurrentContext, key02, Helper.Serialize(info02));
            }
            if (lockCurr03.Length <= 0)
            {
                LockInfo info03 = new LockInfo();
                info03.lockAddr = ethAddr;
                info03.locked = 0;
                info03.lockType = LOCK_TYPE_03;
                info03.owner = addr;
                info03.txid = txid;
                info03.status = 1;
                info03.asset = asset;
                Storage.Put(Storage.CurrentContext, key03, Helper.Serialize(info03));
            }
            if (lockCurr04.Length <= 0)
            {
                LockInfo info04 = new LockInfo();
                info04.lockAddr = ethAddr;
                info04.locked = 0;
                info04.lockType = LOCK_TYPE_04;
                info04.owner = addr;
                info04.txid = txid;
                info04.status = 1;
                info04.asset = asset;
                Storage.Put(Storage.CurrentContext, key04, Helper.Serialize(info04));
            }
            //notify
            Operated(addr, LOCK_TYPE_01.AsByteArray(),(int)ConfigTranType.TRANSACTION_TYPE_OPEN, 0);
            return true;
        }

        private static bool setAccount(string key, byte[] address)
        {
            if (address.Length != 20)
                throw new InvalidOperationException("The parameters address and to SHOULD be 20-byte addresses.");

            Storage.Put(Storage.CurrentContext, getAccountKey(key.AsByteArray()), address);
            return true;
        }

        private static byte[] getAccount(string key) {
            return Storage.Get(Storage.CurrentContext,getAccountKey(key.AsByteArray()));
        }

        private static bool setLockTime(string type,BigInteger time)
        {
            if(time <= 0)
                throw new InvalidOperationException("The parameters time SHOULD be larger than 0.");
            Storage.Put(Storage.CurrentContext,getTimeKey(type),time);
            return true;
        }

        private static BigInteger getLockTime(string type)
        {
            return Storage.Get(Storage.CurrentContext, getTimeKey(type)).AsBigInteger();
        }


        private static byte[] getLockInfo(byte[] addr,string lockType)
        {
            byte[] key = getLockKey(addr,lockType);
            return Storage.Get(Storage.CurrentContext, key);
        }

        private static Boolean withdraw(byte[] addr, string lockType, BigInteger mount)
        {
            if (addr.Length != 20)
                throw new InvalidOperationException("The parameter addr SHOULD be 20-byte addresses.");

            if (mount <= 0)
                throw new InvalidOperationException("The parameter mount MUST be greater than 0.");

            var key = getLockKey(addr, lockType);
            byte[] bytes = getLockInfo(addr, lockType);
            if (bytes.Length == 0) throw new InvalidOperationException("The lockInfo can not be null.");

            LockInfo lockInfo = Helper.Deserialize(bytes) as LockInfo;

            string assetType = lockInfo.asset;
            BigInteger currentLock = lockInfo.locked;
            uint lockTime = lockInfo.lockTime;
            if (currentLock <= 0)
                throw new InvalidOperationException("The lockMount can be greater than 0.");

            byte[] nep5AssetID = Storage.Get(Storage.CurrentContext, getAccountKey(assetType.AsByteArray()));

            //Verify asset security
            if (mount > currentLock)
                throw new InvalidOperationException("The param is exception.");

            //Verify unLock time
            uint nowtime = Blockchain.GetHeader(Blockchain.GetHeight()).Timestamp;
            BigInteger timeInterval = Storage.Get(Storage.CurrentContext,getTimeKey(lockType)).AsBigInteger();
            if((nowtime-lockTime) < timeInterval)
                throw new InvalidOperationException("The unlock time has not come yet.");

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
            lockInfo.locked = currentLock - mount;
            Storage.Put(Storage.CurrentContext, key, Helper.Serialize(lockInfo));

            var globalKey = getLockGlobalKey(LOCK_GLOBAL.AsByteArray());
            BigInteger currentTotal = Storage.Get(Storage.CurrentContext, globalKey).AsBigInteger();
            if (currentTotal - mount >= 0)
            {
                Storage.Put(Storage.CurrentContext, globalKey, currentTotal - mount);
            }
            //notify
            Operated(addr,lockType.AsByteArray(),(int)ConfigTranType.TRANSACTION_TYPE_WITHDRAW, mount);
            return true;
        }

        private static Boolean reserve(byte[] addr,string lockType,BigInteger lockMount)
        {
            if (addr.Length != 20)
                throw new InvalidOperationException("The parameter addr SHOULD be 20-byte addresses.");

            if (lockMount <= 0)
                throw new InvalidOperationException("The parameter lockMount MUST be greater than 0.");

            var key = getLockKey(addr,lockType);
            byte[] bytes = getLockInfo(addr, lockType);
            if (bytes.Length == 0) throw new InvalidOperationException("The lockInfo can not be null.");

            LockInfo lockInfo = Helper.Deserialize(bytes) as LockInfo;

            string assetType = lockInfo.asset;
            BigInteger currentLock = lockInfo.locked;
            if (currentLock > 0)
                throw new InvalidOperationException("The lock has completed.");

            byte[] nep5AssetID = Storage.Get(Storage.CurrentContext, getAccountKey(assetType.AsByteArray()));
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
            lockInfo.locked = lockMount;
            lockInfo.lockHeight = lockHeight;
            lockInfo.lockTime = nowtime;

            Storage.Put(Storage.CurrentContext, key, Helper.Serialize(lockInfo));

            var globalKey = getLockGlobalKey(LOCK_GLOBAL.AsByteArray());
            BigInteger currentTotal = Storage.Get(Storage.CurrentContext, globalKey).AsBigInteger();
            Storage.Put(Storage.CurrentContext,globalKey,currentTotal+lockMount);

            //notify
            Operated(addr, lockType.AsByteArray(),(int)ConfigTranType.TRANSACTION_TYPE_LOCK, lockMount);
            return true;
        }

        private static Boolean close(byte[] addr, string lockType)
        {
            if (addr.Length != 20)
                throw new InvalidOperationException("The parameter addr SHOULD be 20-byte addresses.");

            var key = getLockKey(addr, lockType);
            byte[] bytes = getLockInfo(addr, lockType);
            if (bytes.Length == 0) throw new InvalidOperationException("The lockInfo can not be null.");

            LockInfo lockInfo = Helper.Deserialize(bytes) as LockInfo;

            string assetType = lockInfo.asset;
            BigInteger currentLock = lockInfo.locked;
            if (currentLock > 0)
                throw new InvalidOperationException("The lockMount is not 0.");

            Storage.Delete(Storage.CurrentContext, key);
            //notify
            Operated(addr, lockType.AsByteArray(), (int)ConfigTranType.TRANSACTION_TYPE_SHUT, 0);
            return true;
        }

        public class LockInfo
        {

            //creator
            public byte[] owner;
            //lockAddr,such as eth address
            public string lockAddr;

            //key of this lock
            public byte[] txid;

            //amount of locked collateral
            public BigInteger locked;

            //type of collateral 
            public string lockType;

            //1safe  2unsafe 3lock   
            public int status;

            //lockTime 
            public uint lockTime;

            //lockHeight 
            public uint lockHeight;

            //assetType
            public string asset;

        }
    }
}
