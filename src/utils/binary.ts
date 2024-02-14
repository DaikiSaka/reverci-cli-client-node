export type Move = {
  player: "b" | "w";
  row: number;
  col: number;
  fin?: boolean
};

export const numberToMove = (buffer: number): Move => {
  const byte = buffer;
  // const byte = buffer[0];
  const playerMask = 0b10000000;
  const rowMask = 0b01110000;
  const colMask = 0b00001110;
  const finMask = 0b00000001;
  const player = (byte & playerMask) >> 7 ? "b" : "w";
  const row = (byte & rowMask) >> 4;
  const col = (byte & colMask) >> 1;
  const fin = (byte & finMask) === 1 ?? true;
  return {
    player,
    row,
    col,
    fin
  };
};

export const moveToBuffer = (move: Move): number => {
  let buffer =0;
  if (move.player === "b") buffer += 1
  buffer = buffer << 3;
  buffer += move.row;
  buffer = buffer << 3;
  buffer += move.col;
  buffer = buffer << 1;
  return buffer;
  // return Buffer.alloc(1, buffer);
};

export const test = () => {
  const move: Move[] = [
    { player: "w", row: 3, col: 4 },
    { player: "b", row: 4, col: 4 },
  ];
  move.forEach((m) => {
    const buffer = moveToBuffer(m)
    console.log(buffer.toString(2));
    console.log(numberToMove(buffer));
  });
};

export const bufferToMoves = (buffer: Buffer): Move[] => {
  const moves: Move[] = []
  buffer.forEach(byte=>moves.push(numberToMove(byte)))
  return moves
}

const convertToPosition = (locate: string) => {
  const locates = locate.split("");
  const x = locates[0].toLowerCase();
  const y = Number(locates[1]);
  if (x.charCodeAt(0) < 97 || x.charCodeAt(0) > 104)
    throw new Error("invalid x");
  if (Number.isNaN(y)) throw new Error("invalid y");
  if (y < 1 || y > 8) throw new Error("invalid y");
  return { x: x.charCodeAt(0) - 97, y: y - 1 };
};
