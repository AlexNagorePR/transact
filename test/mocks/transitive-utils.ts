// test/mocks/transitive-utils.ts
export default {
  getLogger: () => ({
    setLevel: () => {},
    debug: () => {},
    info: () => {},
    warn: () => {},
    error: () => {},
  }),
};