export function arbacPatternToRegex(input: string): RegExp {
  let pattern = input.replace(/[$()+\-./?[\\\]^{|}]/gu, "\\$&");
  pattern = pattern.replace(/\*\*/gu, "⁑");
  pattern = pattern.replace(/\*/gu, "[^.]*");
  pattern = pattern.replace(/⁑/gu, ".*");
  return new RegExp(`^${pattern}$`);
}
