type ImportMetaGlobOptions = {
  eager?: boolean
  import?: string
  query?: string | Record<string, string | number | boolean>
}

interface ImportMeta {
  glob<T = unknown>(
    pattern: string | string[],
    options: ImportMetaGlobOptions & { eager: true }
  ): Record<string, T>

  glob<T = unknown>(
    pattern: string | string[],
    options?: ImportMetaGlobOptions & { eager?: false }
  ): Record<string, () => Promise<T>>
}
