/** @type {import("prettier").Config} */
export default {
  useTabs: false,
  tabWidth: 2,
  singleQuote: false,
  trailingComma: "es5",
  semi: false,
  printWidth: 100,
  htmlWhitespaceSensitivity: "ignore",
  jsonRecursiveSort: true,
  plugins: ["@trivago/prettier-plugin-sort-imports", "prettier-plugin-sort-json"],
  importOrder: ["^./(.*)_override.ts$", "<THIRD_PARTY_MODULES>", "^@(.*)$", "^[./]"],
  importOrderSortSpecifiers: true,
}
