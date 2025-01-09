# Tanssi <> Symbiotic

## Description

This repo aims in creating an easy to run environment to spin up a local blockchain network allowing devs to interact with Symbiotic smart contracts.

It allows also to deploy a SimpleMiddleware contract that will be used to interact with the Symbiotic contracts.

This repository provides the necessary infrastructure for deploying and interacting with Symbiotic smart contracts. It includes:

- Symbiotic Contracts: The repository contains the deployment scripts for the core Symbiotic contracts.
- Middleware Contract: In addition to the Symbiotic contracts, the repository also includes a Middleware contract that can be used to interact with the Symbiotic system.
- Rewarder Contract: The repository also includes a Rewarder contract that can be used to distribute rewards to users who interact with the Symbiotic system.

By using this repository, developers can quickly set up the necessary environment for working with Symbiotic contracts, our Middleware and Rewarder.

## Architecture

The architecture can be seen in the following image

![Architecture](./architecture.png)

## Usage

### Install

```shell
$ make install
```

If you have issue with install, delete the `lib` folder.

### Build
```shell
$ make build
```

### Start

To spin up locally the blockchain network run:

```shell
$ make anvil
```

then to deploy symbiotic contracts:

```shell
$ make deploy
```

If you want to emulate the whole process of registering operators and vaults as in mainnet run the demo script:

```shell
$ make demo
```

### Test

```shell
$ make test
```

### Format

```shell
$ make fmt
```

### Gas Snapshots

```shell
$ make snapshot
```

### Clean

```shell
$ make clean
```

If you encounter any issues after continuously deploying contracts, namely `MemoryOOG`, just run:

```shell
$ make clean-all
```

### Remove

```shell
$ make remove
```
