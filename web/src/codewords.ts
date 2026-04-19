import crypto from 'node:crypto';

const ADJECTIVES = [
  'amber', 'azure', 'brave', 'brisk', 'calm', 'cosmic', 'crisp', 'dapper', 'daring', 'deep',
  'eager', 'early', 'electric', 'fabled', 'fair', 'fierce', 'frosty', 'gentle', 'glacier',
  'golden', 'grand', 'graceful', 'hidden', 'humble', 'iron', 'ivory', 'jade', 'jaunty',
  'jolly', 'keen', 'lively', 'lunar', 'lucid', 'merry', 'misty', 'modest', 'noble', 'nimble',
  'olive', 'opal', 'plucky', 'proud', 'quiet', 'quick', 'radiant', 'rapid', 'rosy', 'rugged',
  'sable', 'silent', 'silver', 'solar', 'stellar', 'stoic', 'sturdy', 'sunny', 'swift', 'tawny',
  'teal', 'thunder', 'tidy', 'topaz', 'umber', 'velvet', 'vibrant', 'violet', 'vivid', 'warm',
  'wandering', 'wild', 'winter', 'wise', 'woven', 'yonder', 'zealous', 'zen', 'ember', 'flint',
  'harbor', 'mellow', 'mirth', 'north', 'patient', 'prairie', 'ruby', 'sage', 'shy', 'simple',
  'sleek', 'smoky', 'snow', 'soft', 'spry', 'still', 'stout', 'sunlit', 'tender', 'tranquil',
  'verdant', 'whispering', 'wistful', 'young',
];

const SURNAMES = [
  'abbott', 'adler', 'archer', 'bailey', 'baker', 'barnes', 'bishop', 'brooks', 'burton', 'carver',
  'chase', 'cohen', 'cole', 'cooper', 'crane', 'dale', 'darcy', 'dean', 'dixon', 'doyle',
  'drake', 'ellis', 'finch', 'fisher', 'flynn', 'forge', 'foster', 'frost', 'garcia', 'gibson',
  'grant', 'gray', 'greene', 'hale', 'hamlin', 'harper', 'hayes', 'hicks', 'hoare', 'holt',
  'hughes', 'hunt', 'irving', 'jansen', 'jensen', 'keating', 'kendall', 'kim', 'knox', 'lang',
  'larson', 'leach', 'lee', 'lewis', 'lopez', 'lynch', 'mackay', 'mann', 'marsh', 'mason',
  'mercer', 'miller', 'moss', 'novak', 'nunez', 'ogden', 'olsen', 'orr', 'paige', 'palmer',
  'parker', 'patel', 'pierce', 'quinn', 'rand', 'reeves', 'rhys', 'rios', 'rivera', 'roman',
  'rowe', 'ruiz', 'sawyer', 'shaw', 'shea', 'singh', 'sloan', 'snyder', 'stein', 'stone',
  'tan', 'terry', 'turner', 'vance', 'vega', 'walsh', 'ward', 'webb', 'wells', 'wolfe',
];

function pick<T>(arr: readonly T[]): T {
  const idx = crypto.randomInt(0, arr.length);
  return arr[idx] as T;
}

export function generateCodeword(): string {
  return `${pick(ADJECTIVES)}-${pick(SURNAMES)}`;
}
