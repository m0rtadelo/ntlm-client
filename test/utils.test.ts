import { log } from '../src/utils';


describe('utils test', () => {
  beforeEach(() => {
    console.log = jest.fn();
  });

  it('should load', () => {
    expect(log).toBeDefined();
  });

  it('should log with options.debug = true', () => {
    log({ name: 'test' }, { debug: true }, 'test');
    expect(console.log).toHaveBeenCalled();
  });

  it('should not log with options.debug = false', () => {
    log({ name: 'test' }, { debug: false }, 'test');
    expect(console.log).not.toHaveBeenCalled();
  });

  it('should not log with no options.debug', () => {
    log(undefined, {}, 'test');
    expect(console.log).not.toHaveBeenCalled();
  });

  it('should log with options.debug = true and no context', () => {
    log(undefined, { debug: true }, 'test');
    expect(console.log).toHaveBeenCalled();
  });
});
