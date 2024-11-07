describe("Test Suite", () => {
  describe.each([
    ["registry", "NetworkRegistryAPI.test.ts", "OperatorRegistryAPI.test.ts"],
    ["opt_in", "OptInAPI.test.ts"],
    ["factory", "FactoryAPI.test.ts", "MigratablesFactoryAPI.test.ts"],
  ])("%s", (folderName, ...testFiles) => {
    testFiles.forEach((file) => {
      require(`./${folderName}/${file}`);
    });
  });
});
