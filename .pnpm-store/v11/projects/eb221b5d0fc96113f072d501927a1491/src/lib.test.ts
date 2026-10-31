import {describe,it,expect} from 'vitest';
import {bytes,utc,routeQuery,parseJson} from './lib';
describe('evidence display helpers',()=>{
 it('does not confuse missing values with zero measurements',()=>{expect(bytes(null)).toBe('Unknown');expect(bytes(0)).toBe('0 B');expect(utc(null)).toBe('Unknown');expect(utc('invalid')).toBe('Unknown');});
 it('retains timezone information and safe filter encoding',()=>{expect(utc('2026-10-29T00:00:00Z')).toContain('UTC');expect(routeQuery('/evidence',{q:'a&b',source:''})).toBe('/evidence?q=a%26b');});
 it('handles absent optional JSON without crashing a screen',()=>{expect(parseJson(undefined,[])).toEqual([]);expect(parseJson('{bad',[])).toEqual([]);expect(parseJson('{"n":1}')).toEqual({n:1});});
});
