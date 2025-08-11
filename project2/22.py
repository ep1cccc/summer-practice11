import cv2
import numpy as np
from scipy.fftpack import dct, idct
from skimage import exposure
import random


def block_dct(block):
    # 2D DCT type II (orthonormal)
    return dct(dct(block.T, norm='ortho').T, norm='ortho')

def block_idct(coeff):
    return idct(idct(coeff.T, norm='ortho').T, norm='ortho')


def text_to_bits(s):
    b = ''.join([format(ord(c), '08b') for c in s])
    return np.array([int(x) for x in b], dtype=np.uint8)

def bits_to_text(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            break
        val = int(''.join(str(int(x)) for x in byte), 2)
        chars.append(chr(val))
    return ''.join(chars)


def embed_watermark_dct(cover_img, watermark_bits, strength=10, repeat=3):
    # work on Y channel
    img = cover_img.copy()
    h, w = img.shape[:2]
    ycrcb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb).astype(np.float32)
    Y = ycrcb[:,:,0]

    # pad to multiple of 8
    H = (h + 7) // 8 * 8
    W = (w + 7) // 8 * 8
    pad_h = H - h
    pad_w = W - w
    Yp = np.pad(Y, ((0,pad_h),(0,pad_w)), mode='reflect')

    nblocks_h = H // 8
    nblocks_w = W // 8
    total_blocks = nblocks_h * nblocks_w

    # generate embedding locations: deterministic pseudo-random by seed for reproducibility
    rng = np.random.RandomState(42)  # can be key
    locs = rng.choice(total_blocks, size=min(total_blocks, repeat * len(watermark_bits)), replace=False)

    # mapping each bit to multiple block positions (repeat)
    bit_positions = []
    idx = 0
    for bit in watermark_bits:
        poslist = []
        for r in range(repeat):
            if idx >= len(locs):
                # wrap-around
                idx = 0
            poslist.append(locs[idx])
            idx += 1
        bit_positions.append(poslist)

    # perform embedding
    Y_emb = Yp.copy()
    for bit_index, poslist in enumerate(bit_positions):
        bit = int(watermark_bits[bit_index])
        for pos in poslist:
            by = pos // nblocks_w
            bx = pos % nblocks_w
            y0 = by*8; x0 = bx*8
            block = Yp[y0:y0+8, x0:x0+8]
            B = block_dct(block)
            # choose two mid-frequency coefficients (example positions)
            # Use (4,1) and (3,2) as mid-freq pairs (avoid DC (0,0) and very high)
            i1,j1 = 4,1
            i2,j2 = 3,2
            c1 = B[i1,j1]
            c2 = B[i2,j2]
            # encode: ensure c1 - c2 has correct sign/magnitude
            if bit == 1:
                if c1 - c2 <= 0:
                    # adjust
                    delta = strength + abs(c1 - c2)
                    B[i1,j1] += delta/2
                    B[i2,j2] -= delta/2
            else:
                if c1 - c2 >= 0:
                    delta = strength + abs(c1 - c2)
                    B[i1,j1] -= delta/2
                    B[i2,j2] += delta/2
            # write back
            new_block = block_idct(B)
            Y_emb[y0:y0+8, x0:x0+8] = np.clip(new_block, 0, 255)

    # crop back
    Y_final = Y_emb[:h, :w]
    ycrcb[:,:,0] = Y_final
    out = cv2.cvtColor(ycrcb.astype(np.uint8), cv2.COLOR_YCrCb2BGR)
    return out


def extract_watermark_dct(watermarked_img, watermark_length, repeat=3):
    img = watermarked_img.copy()
    h, w = img.shape[:2]
    ycrcb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb).astype(np.float32)
    Y = ycrcb[:,:,0]

    H = (h + 7) // 8 * 8
    W = (w + 7) // 8 * 8
    pad_h = H - h
    pad_w = W - w
    Yp = np.pad(Y, ((0,pad_h),(0,pad_w)), mode='reflect')

    nblocks_h = H // 8
    nblocks_w = W // 8
    total_blocks = nblocks_h * nblocks_w

    rng = np.random.RandomState(42)
    locs = rng.choice(total_blocks, size=min(total_blocks, repeat * watermark_length), replace=False)

    bit_positions = []
    idx = 0
    for _ in range(watermark_length):
        poslist = []
        for r in range(repeat):
            if idx >= len(locs):
                idx = 0
            poslist.append(locs[idx])
            idx += 1
        bit_positions.append(poslist)

    extracted = []
    for poslist in bit_positions:
        votes = []
        for pos in poslist:
            by = pos // nblocks_w
            bx = pos % nblocks_w
            y0 = by*8; x0 = bx*8
            block = Yp[y0:y0+8, x0:x0+8]
            B = block_dct(block)
            i1,j1 = 4,1
            i2,j2 = 3,2
            c1 = B[i1,j1]
            c2 = B[i2,j2]
            votes.append(1 if (c1 - c2) > 0 else 0)
        # majority vote for this bit
        bit_val = int(round(np.mean(votes)))
        extracted.append(bit_val)
    return np.array(extracted, dtype=np.uint8)


def attack_flip(img):
    return cv2.flip(img, 1)  # horizontal flip

def attack_rotate(img, angle):
    h,w = img.shape[:2]
    M = cv2.getRotationMatrix2D((w/2,h/2), angle, 1.0)
    return cv2.warpAffine(img, M, (w,h), borderMode=cv2.BORDER_REFLECT)

def attack_translate(img, tx, ty):
    h,w = img.shape[:2]
    M = np.float32([[1,0,tx],[0,1,ty]])
    return cv2.warpAffine(img, M, (w,h), borderMode=cv2.BORDER_REFLECT)

def attack_crop(img, crop_frac=0.2):
    h,w = img.shape[:2]
    ch = int(h*(1-crop_frac)); cw = int(w*(1-crop_frac))
    y0 = random.randint(0, h-ch)
    x0 = random.randint(0, w-cw)
    cropped = img[y0:y0+ch, x0:x0+cw]
    # resize back
    return cv2.resize(cropped, (w,h), interpolation=cv2.INTER_LINEAR)

def attack_contrast(img, gamma=1.5):
    # gamma >1 brightens; <1 darkens
    invGamma = 1.0 / gamma
    table = np.array([((i/255.0)**invGamma)*255 for i in np.arange(256)]).astype("uint8")
    return cv2.LUT(img, table)

def attack_gaussian_noise(img, mean=0, var=10):
    sigma = var**0.5
    gauss = np.random.normal(mean, sigma, img.shape).astype(np.float32)
    noisy = img.astype(np.float32) + gauss
    return np.clip(noisy, 0, 255).astype(np.uint8)

def attack_jpeg_compress(img, quality=50):
    encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), quality]
    _, encimg = cv2.imencode('.jpg', img, encode_param)
    decimg = cv2.imdecode(encimg, cv2.IMREAD_COLOR)
    return decimg


def bit_error_rate(original_bits, extracted_bits):
    L = min(len(original_bits), len(extracted_bits))
    if L == 0:
        return 1.0
    return np.sum(original_bits[:L] != extracted_bits[:L]) / L

def normalized_correlation(a, b):
    a = np.array(a).astype(np.float32)
    b = np.array(b).astype(np.float32)
    if a.size == 0 or b.size == 0:
        return 0.0
    L = min(a.size, b.size)
    a = a[:L]; b = b[:L]
    a = 2*a-1  # map {0,1} -> {-1,+1}
    b = 2*b-1
    return float(np.dot(a,b) / (np.sqrt(np.dot(a,a))*np.sqrt(np.dot(b,b))))


def demo_flow(cover_path, watermark_text="hello", out_prefix="out", strength=12, repeat=4):
    cover = cv2.imread(cover_path)
    if cover is None:
        raise RuntimeError("无法读取图片: " + cover_path)
    bits = text_to_bits(watermark_text)
    wm_len = len(bits)
    print(f"Watermark '{watermark_text}' -> {wm_len} bits")

    watermarked = embed_watermark_dct(cover, bits, strength=strength, repeat=repeat)
    cv2.imwrite(f"{out_prefix}_watermarked.png", watermarked)

    # attacks
    attacks = {
        "flip": attack_flip,
        "translate": lambda img: attack_translate(img, tx=10, ty=5),
        "crop": lambda img: attack_crop(img, crop_frac=0.25),
        "contrast": lambda img: attack_contrast(img, gamma=1.6),
        "noise": lambda img: attack_gaussian_noise(img, var=20),
        "jpeg50": lambda img: attack_jpeg_compress(img, quality=50),
    }

    results = {}
    for name, fn in attacks.items():
        attacked = fn(watermarked)
        cv2.imwrite(f"{out_prefix}_attacked_{name}.png", attacked)
        extracted = extract_watermark_dct(attacked, watermark_length=wm_len, repeat=repeat)
        ber = bit_error_rate(bits, extracted)
        nc = normalized_correlation(bits, extracted)
        results[name] = {"ber": ber, "nc": nc, "extracted_text": bits_to_text(extracted)}
        print(f"Attack {name}: BER={ber:.3f}, NC={nc:.3f}, text_snippet='{bits_to_text(extracted)[:30]}'")
    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("image", help="cover image path")
    parser.add_argument("--text", default="secret", help="watermark text")
    parser.add_argument("--out", default="out", help="output prefix")
    args = parser.parse_args()
    demo_flow(args.image, watermark_text=args.text, out_prefix=args.out)
