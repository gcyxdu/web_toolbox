// The first five colors follow the supplied palette; extensions never cycle it.
export const CHART_PALETTE = [
  '#7E99F4',
  '#925EB0',
  '#7AB656',
  '#CC7C71',
  '#A5AEB7',
  '#D3AA60',
  '#55A79E',
  '#CB8EAD',
  '#707EA7',
  '#A2A158',
] as const;

export const METRIC_COLORS = {
  accuracy: CHART_PALETTE[0],
  loss: CHART_PALETTE[1],
  asr: CHART_PALETTE[3],
};

function extraColor(index: number): string {
  const hue = ((index * 137.507764) % 360) / 60;
  const chroma = 0.5;
  const x = chroma * (1 - Math.abs((hue % 2) - 1));
  const rgb =
    hue < 1
      ? [chroma, x, 0]
      : hue < 2
        ? [x, chroma, 0]
        : hue < 3
          ? [0, chroma, x]
          : hue < 4
            ? [0, x, chroma]
            : hue < 5
              ? [x, 0, chroma]
              : [chroma, 0, x];
  return (
    '#' +
    rgb
      .map((value) =>
        Math.round((value + 0.24) * 255)
          .toString(16)
          .padStart(2, '0'),
      )
      .join('')
      .toUpperCase()
  );
}

export function chartColors(count: number): string[] {
  const colors: string[] = [...CHART_PALETTE].slice(0, count);
  const used = new Set(colors);
  for (let index = 0; colors.length < count; index++) {
    const color = extraColor(index);
    if (!used.has(color)) {
      colors.push(color);
      used.add(color);
    }
  }
  return colors;
}

export function distinctChartColors(preferred: string[]): string[] {
  const alternatives = chartColors(preferred.length + CHART_PALETTE.length);
  const reserved = new Set(preferred.map((value) => value.trim().toUpperCase()).filter(Boolean));
  const used = new Set<string>();
  return preferred.map((value) => {
    const requested = value.trim().toUpperCase();
    const color =
      requested && !used.has(requested)
        ? requested
        : alternatives.find((candidate) => !used.has(candidate) && !reserved.has(candidate))!;
    used.add(color);
    return color;
  });
}
