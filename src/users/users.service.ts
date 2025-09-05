import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './user.schema';

@Injectable()
export class UsersService {
  constructor(@InjectModel("User") private model: Model<User>) {}

  findByEmail(email: string) {
    return this.model.findOne({ email }).lean();
  }
  findById(id: string) {
    return this.model.findById(id).lean();
  }

  async create(input: Partial<User>) {
    const doc = new this.model(input);
    await doc.save();
    return { id: doc._id.toString(), email: doc.email, name: doc.name };
  }
}
