import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Session } from './session.schema';
import { createHash, randomUUID } from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    private users: UsersService,
    private jwt: JwtService,
    @InjectModel(Session.name) private sessions: Model<Session>,
  ) {}

  private hashCreator(token: string) {
    return createHash('sha256').update(token).digest('hex');
  }

  signAccess(userId: string, email: string) {
    return this.jwt.signAsync(
      { sub: userId, email },
      {
        secret: process.env.JWT_ACCESS_SECRET!,
        expiresIn: Number(process.env.JWT_ACCESS_TTL || 900),
      },
    );
  }

  signRefresh(userId: string, sid: string) {
    return this.jwt.signAsync(
      { sub: userId, sid },
      {
        secret: process.env.JWT_REFRESH_SECRET!,
        expiresIn: Number(process.env.JWT_REFRESH_TTL || 2592000),
      },
    );
  }

  async signup(
    email: string,
    password: string,
    name?: string,
    ua?: string,
    ip?: string,
  ) {
    const existing = await this.users.findByEmail(email.toLowerCase());
    if (existing) throw new BadRequestException('Email already in use');

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = await this.users.create({
      email: email.toLowerCase(),
      password: hashedPassword,
      name,
    });

    const sid = randomUUID();
    const accessToken = await this.signAccess(user.id.toString(), user.email);
    const refreshToken = await this.signRefresh(user.id.toString(), sid);

    const ttlSec = Number(process.env.JWT_REFRESH_TTL || 2592000);
    await this.sessions.create({
      userId: user.id.toString(),
      refreshTokenHash: this.hashCreator(refreshToken),
      userAgent: ua,
      ip,
      expiresAt: new Date(Date.now() + ttlSec * 1000),
    });

    return {
      accessToken,
      refreshToken,
      user: { id: user.id, email: user.email, name: user.name },
    };
  }

  async login(email: string, password: string, ua?: string, ip?: string) {
    const user = await this.users.findByEmail(email.toLowerCase());
    if (!user) throw new UnauthorizedException('Invalid credentials');
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) throw new UnauthorizedException('Invalid credentials');

    const sid = randomUUID();
    const accessToken = await this.signAccess(user._id.toString(), user.email);
    const refreshToken = await this.signRefresh(user._id.toString(), sid);

    const ttlSec = Number(process.env.JWT_REFRESH_TTL || 2592000);
    await this.sessions.create({
      userId: user._id.toString(),
      refreshTokenHash: this.hashCreator(refreshToken),
      userAgent: ua,
      ip,
      expiresAt: new Date(Date.now() + ttlSec * 1000),
    });

    return {
      accessToken,
      refreshToken,
      user: { id: user._id, email: user.email, name: user.name },
    };
  }

  async refresh(oldRt: string, ua?: string, ip?: string) {
    try {
      const payload = await this.jwt.verifyAsync(oldRt, {
        secret: process.env.JWT_REFRESH_SECRET!,
      });
      const { sub: userId, sid } = payload as any;
      const session = await this.sessions
        .findOne({
          userId,
          replacedBy: { $exists: false },
          revokedAt: { $exists: false },
        })
        .sort({ createdAt: -1 })
        .lean();
      if (!session) throw new UnauthorizedException();
      if (this.hashCreator(oldRt) !== session.refreshTokenHash)
        throw new UnauthorizedException();

      const newSid = randomUUID();
      const accessToken = await this.signAccess(
        userId,
        (await this.users.findById(userId))!.email,
      );
      const refreshToken = await this.signRefresh(userId, newSid);
      const ttlSec = Number(process.env.JWT_REFRESH_TTL || 2592000);

      // mark old revoked and insert new
      await this.sessions.updateOne(
        { _id: session._id },
        { $set: { revokedAt: new Date(), replacedBy: newSid } },
      );
      await this.sessions.create({
        userId,
        refreshTokenHash: this.hashCreator(refreshToken),
        userAgent: ua,
        ip,
        expiresAt: new Date(Date.now() + ttlSec * 1000),
      });

      return { accessToken, refreshToken };
    } catch {
      throw new UnauthorizedException();
    }
  }

  async logout(rt: string) {
    try {
      const { sid } = (await this.jwt.verifyAsync(rt, {
        secret: process.env.JWT_REFRESH_SECRET!,
      })) as any;
      await this.sessions.updateOne(
        { replacedBy: sid },
        { $set: { revokedAt: new Date() } },
      ); // best-effort
    } catch {}
    return { ok: true };
  }

  async logoutAll(userId: string) {
    await this.sessions.updateMany(
      { userId, revokedAt: { $exists: false } },
      { $set: { revokedAt: new Date() } },
    );
    return { ok: true };
  }
}
