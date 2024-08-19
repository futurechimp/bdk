use std::str::FromStr;

use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::hashes::Hash;
use bdk_wallet::bitcoin::key::Secp256k1;

use bdk_wallet::bitcoin::{
    self, psbt, Address, Network, OutPoint, Psbt, Script, Sequence, Transaction, TxIn, TxOut, Txid,
};

use bdk_wallet::keys::DescriptorPublicKey;
use bdk_wallet::miniscript::plan::Assets;
use bdk_wallet::miniscript::policy::Concrete;
use bdk_wallet::miniscript::psbt::PsbtExt;
use bdk_wallet::miniscript::{DefiniteDescriptorKey, Descriptor};
use bdk_wallet::{KeychainKind, Wallet};
use bitcoin::{absolute, transaction, Amount};

// Using a descriptor and spending plans with BDK wallets.
//
// Consider the basic flow of using a descriptor. The steps are:
// 1. Set up the Descriptor
// 2. Deposit sats into the descriptor
// 3. Get the previous output and witness from the deposit transaction
// 4. Set up a psbt to spend the deposited funds
// 5. If there are multiple spend paths, use the `plan` module to format the psbt properly
// 6. Sign the spending psbt
// 7. Finalize the psbt. At this point, miniscript will check whether the transaction
//   satisfies the descriptor, and will notify you if it doesn't.
// 8. If desired, extract the transaction from the psbt and broadcast it.
fn main() {
    // In order to try out descriptors, let's define a Bitcoin vault with two spend paths.
    //
    // The vault works like this:
    //
    // A. If you have the `unvault_key`, you can spend the funds, but only *after* a specified block height
    // B. If you have the `emergency_key`, presumably kept in deep cold storage, you can spend at any time.

    // Let's set up some wallets so we have keys to work with.

    // Regular unvault spend path keys + blockheight. You can use wallet descriptors like this,
    // or you could potentially use a mnemonic and derive from that. See the `mnemonic_to_descriptors.rs`
    // example if you want to do that.
    let unvault_tprv = "tprv8ZgxMBicQKsPdKyH699thnjrFcmJMrUUoaNZvHYxxqvhySPhAYZpmxtR39u5QAYnhtYSfMBuBBH6pGuSgmoK3NpfNDU3RAbrVpcbpLmz5ot";
    let unvault_pk = "02e7c62fd3a65abdc7ff233fba5637f89c9eaba7fe6baaf15ca99d81e0f5145bf8";
    let after = 1311208;

    // Emergency path keys
    let emergency_tprv = "tprv8ZgxMBicQKsPekKEvzvCnK7qe5r6ausugHDyrPeX9TLQ4oADSYLWtA4m3XsEMmUZEbVaeJtuZimakomLkecLTMwerVJKpAZFtXoo7DYb84B";
    let emergency_pk = "033b4ac89f5d83de29af72d8b99963c4dbd416fa7c8a8aee6b4761f8f85e588f80";

    // Make a wallet for the unvault user
    let unvault_desc = format!("wpkh({unvault_tprv}/84'/1'/0'/0/*)");
    let unvault_change_desc = format!("wpkh({unvault_tprv}/84'/1'/0'/1/*)");
    let mut unvault_wallet = Wallet::create(unvault_desc, unvault_change_desc)
        .network(Network::Testnet)
        .create_wallet_no_persist()
        .expect("couldn't create unvault_wallet");

    // Make a wallet for the emergency user
    let emergency_desc = format!("wpkh({emergency_tprv}/84'/1'/0'/0/*)");
    let emergency_change_desc = format!("wpkh({emergency_tprv}/84'/1'/0'/1/*)");
    let mut emergency_wallet = Wallet::create(emergency_desc, emergency_change_desc)
        .network(Network::Testnet)
        .create_wallet_no_persist()
        .expect("couldn't create emergency_wallet");

    // 1. Set up the Descriptor

    // The following string defines a miniscript vault policy with two possible spend paths (`or`):
    // * spend at any time with the `emergency_pk`
    // * spend `after` the timelock with the `unvault_pk`
    let policy_str = format!("or(pk({emergency_pk}),and(pk({unvault_pk}),after({after})))");

    // Set up the Policy
    let policy =
        Concrete::<DefiniteDescriptorKey>::from_str(&policy_str).expect("couldn't create policy");

    // Compile the policy
    let vault_policy = policy.compile().expect("policy compilation failed");
    println!("The vault policy is: {}\n", vault_policy);

    // Turn the policy into a `Descriptor`.
    let vault_descriptor = Descriptor::new_wsh(vault_policy).expect("could not create descriptor");
    println!("The vault descriptor is: {}\n", vault_descriptor);

    // 2. Deposit sats into the descriptor

    // Descriptors have script pubkeys that you can send funds to using a normal funds
    // transfer:
    println!(
        "Our vault descriptor has a script_pubkey: {}\n",
        vault_descriptor.script_pubkey()
    );

    // Alternately, we can make a wallet for our vault and get its address:
    let mut vault = Wallet::create_single(vault_descriptor.to_string())
        .network(Network::Testnet)
        .create_wallet_no_persist()
        .unwrap();
    let vault_address = vault.peek_address(KeychainKind::External, 0).address;
    println!("The vault address is {:?}", vault_address);

    // We don't need to broadcast the funding transaction in this tutorial -
    // having it locally is good enough to get the information we need, and it saves
    // messing around with faucets etc.

    // Fund the vault by inserting a transaction:
    let deposit_tx = deposit_transaction(vault_address);
    vault.insert_tx(deposit_tx.clone());

    // 3. Get the previous output and witness from the deposit transaction. In a real application
    // you would get this from the blockchain if you didn't make the deposit_tx.
    let (previous_output, witness_utxo) = get_vout(&deposit_tx, &vault_descriptor.script_pubkey());
    println!(
        "The deposit transaction's outpoint was  {} \n The deposit transaction's witness utxo was: {:#?} ",
        previous_output, witness_utxo
    );

    // 4. Set up a psbt to spend the deposited funds
    println!("Setting up a psbt for the emergency spend path");
    let emergency_spend = blank_transaction();
    let mut psbt =
        Psbt::from_unsigned_tx(emergency_spend).expect("couldn't create psbt from emergency_spend");

    // Format an input containing the previous output
    let txin = TxIn {
        previous_output,
        ..Default::default()
    };

    // Format an output which spends some of the funds in the vault
    let txout = TxOut {
        script_pubkey: emergency_wallet
            .next_unused_address(KeychainKind::External)
            .script_pubkey(),
        value: Amount::from_sat(750),
    };

    // Add the TxIn and TxOut to the transaction we're working on
    psbt.unsigned_tx.input.push(txin);
    psbt.unsigned_tx.output.push(txout);

    // 5. If there are multiple spend paths, use the `plan` module to format the psbt properly

    // Our vault happens to have two spend paths, and the miniscript satisfier will freak out
    // if we don't tell it which path we're formatting this transaction for. It's like a
    // compile-time check vs a runtime check.
    //
    // In order to tell it whether we are trying for the unvault + timelock spend path,
    // or the emergency spend path, we can use the `plan` module from `rust-miniscript`.
    //
    // The plan module says: "given x assets, can I satisfy the
    // miniscript descriptor y?". It can also automatically update the psbt
    // with the information. When the psbt is finalized, miniscript will check
    // whether the formatted transaction can satisfy the descriptor or not.

    // Let's try using the plan module on the emergency spend path.

    // First we define our emergency key as a possible asset we can use in the plan
    // to attempt to satisfy the descriptor.
    println!("Adding a spending plan to the emergency spend psbt");
    let emergency_key_asset = DescriptorPublicKey::from_str(emergency_pk).unwrap();

    // Then we add the emergency key to our list of plan assets. If we had more than one
    // asset (e.g. multiple keys, timelocks, etc) in the descriptor branch we are trying
    // to spend on, we would define and add multiple assets.
    let assets = Assets::new().add(emergency_key_asset);

    // Automatically generate a plan for spending the descriptor
    let emergency_plan = vault_descriptor
        .clone()
        .plan(&assets)
        .expect("couldn't create emergency plan");

    // Create an input where we can put the plan data
    // Add the witness_utxo from the deposit transaction to the input
    println!("Adding deposit transaction's witness output to the emergency spend psbt");
    let mut input = psbt::Input {
        witness_utxo: Some(witness_utxo.clone()),
        ..Default::default()
    };

    // Update the input with the generated plan
    println!("Update the emergency spend psbt with spend plan");
    emergency_plan.update_psbt_input(&mut input);

    // Push the input to the PSBT
    psbt.inputs.push(input);

    // Add a default output to the PSBT
    psbt.outputs.push(psbt::Output::default());

    // 6. Sign the spending psbt

    // At this point, we have a PSBT that is ready to be signed.
    // It contains public data in its inputs, and data which needs to be signed
    // in its `unsigned_tx.{input, output}s`

    // Sign the psbt
    println!("Signing emergency spend psbt");
    let secp = Secp256k1::new();
    let emergency_key = Xpriv::from_str(emergency_tprv).expect("couldn't create emergency key");
    psbt.sign(&emergency_key, &secp)
        .expect("failed to sign emergency spend psbt");

    // 7. Finalize the psbt. At this point, miniscript will check whether the transaction
    //   satisfies the descriptor, and will notify you if it doesn't.

    psbt.finalize_mut(&secp)
        .expect("problem finalizing emergency psbt");
    println!("Finalized emergency spend psbt");

    // 8. If desired, extract the transaction from the psbt and broadcast it. We won't do this
    // here as it saves messing around with faucets, wallets, etc.
    let _my_emergency_spend_tx = psbt.extract_tx().expect("failed to extract emergency tx");

    // Let's now try the same thing with the unvault transaction. We just need to make a new
    // plan, sign a new spending psbt, and finalize it.

    // Build a spend transaction the unvault key path
    println!("Setting up a psbt for the unvault spend path");
    let timelock = absolute::LockTime::from_height(after).expect("couldn't format locktime");
    let unvault_spend_transaction = blank_transaction_with(timelock);
    let mut psbt = Psbt::from_unsigned_tx(unvault_spend_transaction)
        .expect("couldn't create psbt from unvault_spend_transaction");

    // Format an input containing the previous output (we got that already using `get_vout()`)
    println!("Adding deposit transaction's witness output to the unvault spend psbt");
    let txin = TxIn {
        previous_output,
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, // disables relative timelock
        ..Default::default()
    };

    // Format an output which spends some of the funds in the vault.
    let txout = TxOut {
        script_pubkey: unvault_wallet
            .next_unused_address(KeychainKind::External)
            .script_pubkey(),
        value: Amount::from_sat(750),
    };

    // Add the TxIn and TxOut to the transaction we're working on
    psbt.unsigned_tx.input.push(txin);
    psbt.unsigned_tx.output.push(txout);

    // Let's try using the Plan module, this time with two assets: the unvault_key
    // and our `after` timelock.
    println!("Adding a spending plan to the unvault spend psbt");
    let unvault_key_asset = DescriptorPublicKey::from_str(unvault_pk).unwrap();
    let timelock = absolute::LockTime::from_height(after).expect("couldn't format locktime");
    let unvault_assets = Assets::new().add(unvault_key_asset).after(timelock);

    // Automatically generate a plan for spending the descriptor, using the assets in our plan
    let unvault_plan = vault_descriptor
        .clone()
        .plan(&unvault_assets)
        .expect("couldn't create plan");

    // Create an input where we can put the plan data
    // Add the witness_utxo from the deposit transaction to the input
    let mut input = psbt::Input {
        witness_utxo: Some(witness_utxo.clone()),
        ..Default::default()
    };

    // Update the input with the generated plan
    println!("Update the unvault spend psbt with spend plan");
    unvault_plan.update_psbt_input(&mut input);

    // Push the input to the PSBT
    psbt.inputs.push(input);

    // Add a default output to the PSBT
    psbt.outputs.push(psbt::Output::default());

    // Sign it
    println!("Signing unvault spend psbt");
    let secp = Secp256k1::new();
    let unvault_key = Xpriv::from_str(unvault_tprv).unwrap();
    psbt.sign(&unvault_key, &secp)
        .expect("failed to sign unvault psbt");

    // Finalize the psbt. Miniscript satisfier checks are run at this point,
    // and if your transaction doesn't satisfy the descriptor, this will error.
    psbt.finalize_mut(&secp)
        .expect("problem finalizing unvault psbt");
    println!("Finalized unvault spend psbt");

    // Once again, we could broadcast the transaction if we wanted to
    // spend using the unvault path. Spend attempts will fail until
    // after the absolute block height defined in the timelock.
    let _my_unvault_tx = psbt.extract_tx().expect("failed to extract unvault tx");

    println!("Congratulations, you've just used a miniscript descriptor with a BDK wallet!");
    println!("Read the code comments for a more detailed look at what happened.")
}

// Find the OutPoint by spk, useful for ensuring that we grab the right
// output transaction to use as input for our spend transaction
fn get_vout(tx: &Transaction, spk: &Script) -> (OutPoint, TxOut) {
    for (i, txout) in tx.clone().output.into_iter().enumerate() {
        if spk == &txout.script_pubkey {
            return (OutPoint::new(tx.compute_txid(), i as u32), txout);
        }
    }
    panic!("Only call get vout on functions which have the expected outpoint");
}

fn blank_transaction() -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO, // disables relative timelock
        input: vec![],
        output: vec![],
    }
}

fn blank_transaction_with(lock_time: absolute::LockTime) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: transaction::Version::TWO,
        lock_time,
        input: vec![],
        output: vec![],
    }
}

fn deposit_transaction(receive_address: Address) -> bitcoin::Transaction {
    Transaction {
        version: transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0,
            },
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(76_000),
            script_pubkey: receive_address.script_pubkey(),
        }],
    }
}
